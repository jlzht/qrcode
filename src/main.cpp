#include <chrono>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <optional>
#include <random>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "crow.h"
#include "qrcodegen/qrcodegen.hpp"
#include <crypt.h>
#include <getopt.h>
#include <openssl/sha.h>
#include <sqlite3.h>

// TODO:
// - separar classes em arquivos
// - importar so os headers do crow necessarios

std::string extract_token_from_cookie(const std::string &cookie_header) {
  auto pos = cookie_header.find("session_id=");
  if (pos == std::string::npos)
    return "";

  auto token = cookie_header.substr(pos + 11);
  auto end = token.find(';');
  return (end != std::string::npos) ? token.substr(0, end) : token;
}

class LeaderboardManager {
public:
  using entry = std::pair<std::string, int>;

  LeaderboardManager(sqlite3 *db) : db_(db) { update(); }

  const std::vector<entry> &top() const {
    std::lock_guard<std::mutex> lock(leaderboard_mutex_);
    return cached_top_;
  }

  void update() {
    std::vector<entry> current;
    const char *sql =
        "SELECT name, score FROM scores ORDER BY score DESC LIMIT 50;";
    sqlite3_stmt *stmt = nullptr;

    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
      while (sqlite3_step(stmt) == SQLITE_ROW) {
        std::string name =
            reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0));
        int score = sqlite3_column_int(stmt, 1);
        current.emplace_back(name, score);
      }
    } else {
      std::cerr << "Update() SQL error: " << sqlite3_errmsg(db_) << "\n";
    }
    sqlite3_finalize(stmt);

    std::string current_hash = compute_hash(current);
    std::lock_guard<std::mutex> lock(leaderboard_mutex_);
    if (current_hash != last_hash_) {
      cached_top_ = std::move(current);
      last_hash_ = std::move(current_hash);
      std::cout << "Leaderboard cache updated\n";
    } else {
      std::cout << "Leaderboard unchanged\n";
    }
  }

  void submit(const std::string &name, int score) {
    const char *sql = R"(
            INSERT INTO scores (name, score) VALUES (?, ?)
            ON CONFLICT(name) DO UPDATE SET score = score + excluded.score
        )";

    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
      sqlite3_bind_text(stmt, 1, name.c_str(), -1, SQLITE_TRANSIENT);
      sqlite3_bind_int(stmt, 2, score);
      sqlite3_step(stmt);
    } else {
      std::cerr << "Submit() SQL error: " << sqlite3_errmsg(db_) << "\n";
    }
    sqlite3_finalize(stmt);
  }

private:
  sqlite3 *db_;
  std::vector<entry> cached_top_;
  std::string last_hash_;
  mutable std::mutex leaderboard_mutex_;

  static std::string compute_hash(const std::vector<entry> &data) {
    std::ostringstream oss;
    for (const auto &[name, score] : data)
      oss << name << ":" << score << ";";

    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char *>(oss.str().c_str()),
           oss.str().size(), digest);

    std::ostringstream hex_stream;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
      hex_stream << std::hex << std::setw(2) << std::setfill('0')
                 << static_cast<int>(digest[i]);

    return hex_stream.str();
  }
};

class SessionManager {
public:
  using clock = std::chrono::steady_clock;
  using time = clock::time_point;

  SessionManager(sqlite3 *db, int session_timeout_sec = 1800)
      : db_(db), session_timeout_(session_timeout_sec) {}

  std::string login(const std::string &username, const std::string &password) {
    std::string stored_hash;
    const char *sql = "SELECT password_hash FROM users WHERE username = ?;";
    sqlite3_stmt *stmt = nullptr;

    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
      return "";

    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt) == SQLITE_ROW)
      stored_hash =
          reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0));
    sqlite3_finalize(stmt);

    if (stored_hash.empty() || !check_password(password, stored_hash))
      return "";

    std::string token = generate_token();
    std::lock_guard<std::mutex> lock(session_mutex_);
    sessions_[token] = {username, clock::now()};
    return token;
  }

  void logout(const std::string &token) {
    std::lock_guard<std::mutex> lock(session_mutex_);
    sessions_.erase(token);
  }

  bool register_user(const std::string &username, const std::string &password) {
    std::string hashed = hash_password(password);
    if (hashed.empty())
      return false;

    const char *sql =
        "INSERT INTO users (username, password_hash) VALUES (?, ?);";
    sqlite3_stmt *stmt = nullptr;

    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
      return false;

    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, hashed.c_str(), -1, SQLITE_TRANSIENT);
    bool ok = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return ok;
  }

  std::optional<std::string> get_user(const crow::request &req) {
    std::string token =
        extract_token_from_cookie(req.get_header_value("Cookie"));

    std::lock_guard<std::mutex> lock(session_mutex_);
    auto it = sessions_.find(token);
    if (it == sessions_.end())
      return std::nullopt;

    auto now = clock::now();
    auto diff = now - it->second.last_seen;
    auto duration =
        std::chrono::duration_cast<std::chrono::seconds>(diff).count();
    if (duration > session_timeout_) {
      sessions_.erase(it);
      return std::nullopt;
    }

    it->second.last_seen = now;
    return it->second.username;
  }

private:
  sqlite3 *db_;
  int session_timeout_;

  struct SessionInfo {
    std::string username;
    time last_seen;
  };
  std::unordered_map<std::string, SessionInfo> sessions_;
  mutable std::mutex session_mutex_;

  std::string generate_token() {
    static const std::string charset = "0123456789abcdef";
    static std::mt19937 rng(std::random_device{}());
    std::string token;
    std::uniform_int_distribution<> dist(0, charset.size() - 1);

    for (int i = 0; i < 64; ++i)
      token += charset[dist(rng)];

    return token;
  }

  std::string hash_password(const std::string &password) {
    char salt[64];
    if (!crypt_gensalt_rn("$6$", 16, nullptr, 0, salt, sizeof(salt)))
      return "";

    struct crypt_data data {};
    char *hashed = crypt_rn(password.c_str(), salt, &data, sizeof(data));
    return hashed ? std::string(hashed) : "";
  }

  bool check_password(const std::string &password, const std::string &hash) {
    struct crypt_data data {};
    char *result =
        crypt_rn(password.c_str(), hash.c_str(), &data, sizeof(data));
    return result && hash == result;
  }
};

class RouteGenerator {
public:
  using map = std::unordered_map<std::string, std::string>;

  RouteGenerator(const std::string &input, const std::string &output)
      : input_(input), output_(output) {}

  void generate() {
    std::ifstream in(input_);
    if (!in.is_open()) {
      std::cerr << "Could not open input file: " << input_ << "\n";
      return;
    }

    std::ofstream out(output_);
    if (!out.is_open()) {
      std::cerr << "Could not open output file: " << output_ << "\n";
      return;
    }

    std::string name;
    while (std::getline(in, name)) {
      if (name.empty())
        continue;

      std::string hash = generate_hash(name);
      routes_[name] = hash;
      out << name << "," << hash << "\n";
    }

    std::cout << "Generated routes.csv successfully\n";
  }

  bool load() {
    std::ifstream in(output_);
    if (!in.is_open()) {
      std::cerr << "Could not open routes file: " << output_ << "\n";
      return false;
    }

    std::string line;
    while (std::getline(in, line)) {
      if (line.empty())
        continue;
      auto comma = line.find(',');
      if (comma == std::string::npos)
        continue;

      std::string name = line.substr(0, comma);
      std::string hash = line.substr(comma + 1);
      routes_[name] = hash;
    }

    std::cout << "Loaded routes from file: " << output_ << "\n";
    return true;
  }

  bool check_routes() const {
    std::ifstream in(input_);
    std::ifstream out(output_);
    int input_lines = 0, output_lines = 0;
    std::string line;

    while (std::getline(in, line))
      if (!line.empty())
        ++input_lines;
    while (std::getline(out, line))
      if (!line.empty())
        ++output_lines;

    if (input_lines != output_lines) {
      std::cerr << "Line mismatch: " << input_lines << " names vs "
                << output_lines << " routes.\n";
      return false;
    }

    return true;
  }

  const map &get() const { return routes_; }

private:
  std::string input_;
  std::string output_;
  map routes_;

  std::string generate_hash(const std::string &name) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dist(0, 255);

    std::ostringstream oss;
    for (int i = 0; i < 16; ++i) {
      oss << std::hex << std::setw(2) << std::setfill('0') << dist(gen);
    }
    std::string salt = oss.str();

    std::string input = name + salt;

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char *>(input.c_str()), input.size(),
           hash);

    std::ostringstream hex;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
      hex << std::hex << std::setw(2) << std::setfill('0')
          << static_cast<int>(hash[i]);
    }

    return hex.str();
  }
};

class QrGenerator {
public:
  using qr_code = qrcodegen::QrCode;

  QrGenerator(const std::string &path, const std::string &prefix)
      : path_(path), prefix_(prefix) {}

  void generate() {
    std::ifstream file(path_);

    if (!file.is_open()) {
      std::cerr << "Could not open routes file: " << path_ << "\n";
      return;
    }

    std::filesystem::path base = std::filesystem::path(path_).parent_path();
    std::filesystem::path qr_dir = base / "qrcodes";
    if (std::filesystem::exists(qr_dir)) {
      if (!std::filesystem::is_directory(qr_dir)) {
        std::cerr << " Path is not a directory. Delete or rename it.\n";
        return;
      }
    } else {
      std::filesystem::create_directories(qr_dir);
    }

    std::string line;
    while (std::getline(file, line)) {
      auto comma = line.find(',');
      if (comma == std::string::npos)
        continue;

      std::string name = line.substr(0, comma);
      std::string route = line.substr(comma + 1);
      std::string url = prefix_ + route;

      qr_code qr = qr_code::encodeText(url.c_str(), qr_code::Ecc::LOW);
      std::string svg = to_svg(qr, 4);

      std::filesystem::path out_path = qr_dir / ("qr_" + name + ".svg");
      std::ofstream out(out_path);
      if (!out) {
        std::cerr << "Could not write SVG for " << name << "\n";
        continue;
      }

      out << svg;
      std::cout << "Saved " << out_path << "\n";
    }
  }

  bool check_qrcodes() const {
    std::filesystem::path base = std::filesystem::path(path_).parent_path();
    std::filesystem::path qr_dir = base / "qrcodes";

    if (!std::filesystem::exists(qr_dir))
      return false;
    if (!std::filesystem::is_directory(qr_dir)) {
      std::cerr << "Path is not a directory.\n";
      return false;
    }

    std::ifstream file(path_);
    if (!file.is_open())
      return false;

    int expected = 0;
    std::string line;
    while (std::getline(file, line)) {
      if (!line.empty())
        ++expected;
    }

    int actual = 0;
    for (auto &entry : std::filesystem::directory_iterator(qr_dir)) {
      if (entry.path().extension() == ".svg")
        ++actual;
    }

    return expected == actual;
  }

private:
  std::string path_;
  std::string prefix_;

  std::string to_svg(const qr_code &qr, int border) {
    std::ostringstream sb;
    sb << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    sb << "<svg xmlns=\"http://www.w3.org/2000/svg\" version=\"1.1\" "
          "viewBox=\"0 0 ";
    sb << (qr.getSize() + border * 2) << " " << (qr.getSize() + border * 2)
       << "\" stroke=\"none\">\n";
    sb << "\t<rect width=\"100%\" height=\"100%\" fill=\"#FFFFFF\"/>\n";
    sb << "\t<path d=\"";
    for (int y = 0; y < qr.getSize(); y++) {
      for (int x = 0; x < qr.getSize(); x++) {
        if (qr.getModule(x, y)) {
          if (x != 0 || y != 0)
            sb << " ";
          sb << "M" << (x + border) << "," << (y + border) << "h1v1h-1z";
        }
      }
    }
    sb << "\" fill=\"#000000\"/>\n";
    sb << "</svg>\n";
    return sb.str();
  }
};

bool init_db(sqlite3 *db) {
  const char *schema = R"(
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS scores (
            name TEXT PRIMARY KEY,
            score INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS visits (
            user_id INTEGER NOT NULL,
            token TEXT NOT NULL,
            PRIMARY KEY (user_id, token),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    )";

  char *err = nullptr;
  int rc = sqlite3_exec(db, schema, nullptr, nullptr, &err);

  if (rc != SQLITE_OK) {
    std::cerr << "Database init error: " << err << "\n";
    sqlite3_free(err);
    return false;
  }

  std::cout << "Database initialized successfully\n";
  return true;
}

sqlite3 *db = nullptr;

int main(int argc, char *argv[]) {
  std::string input, output, domain, template_dir;
  int port = 8080;

  int opt;
  while ((opt = getopt(argc, argv, "i:o:p:d:t:")) != -1) {
    switch (opt) {
    case 'i':
      input = optarg;
      break;
    case 'o':
      output = optarg;
      break;
    case 'p':
      port = std::stoi(optarg);
      break;
    case 'd':
      domain = optarg;
      break;
    case 't':
      template_dir = optarg;
      break;
    default:
      std::cerr << "Usage: " << argv[0]
                << " -i input.csv -o output.csv -p port -t template_folder\n";
      return 1;
    }
  }

  if (!std::filesystem::exists(input)) {
    std::cerr << "Input file does not exist: " << input << "\n";
    return 1;
  }

  RouteGenerator routes(input, output);
  if (!routes.check_routes()) {
    routes.generate();
  } else {
    std::cout << "Routes already exist. Skipping generation.\n";
  }

  if (!std::filesystem::exists(output) || !routes.check_routes()) {
    std::cout << "Generating routes.csv...\n";
    routes.generate();
  } else {
    routes.load();
    std::cout << "Routes file is consistent. Skipping generation.\n";
  }

  QrGenerator qrs(output, domain);
  if (!qrs.check_qrcodes()) {
    std::cout << "Generating QR codes...\n";
    qrs.generate();
  } else {
    std::cout << "All QR codes are up-to-date. Skipping generation.\n";
  }

  if (sqlite3_open("qr.db", &db) != SQLITE_OK) {
    std::cerr << "Could not open database: " << sqlite3_errmsg(db) << "\n";
    return 1;
  }

  if (!init_db(db)) {
    sqlite3_close(db);
    std::cout << "Error openning database.\n";
    return 1;
  }

  LeaderboardManager leaderboard(db);
  SessionManager session(db);

  crow::SimpleApp app;
  crow::mustache::set_base(template_dir);

  CROW_ROUTE(app, "/home")
  ([&session](const crow::request &req) {
    crow::mustache::context ctx;
    ctx["title"] = "Página Inicial";

    auto user = session.get_user(req);
    if (user && !user->empty())
      ctx["user"] = *user;

    return crow::mustache::load("home.mustache").render(ctx);
  });

  CROW_ROUTE(app, "/signup")
  ([] {
    crow::mustache::context ctx;
    ctx["title"] = "Registrar";
    return crow::mustache::load("signup.mustache").render(ctx);
  });

  CROW_ROUTE(app, "/signup")
      .methods(crow::HTTPMethod::POST)([&session](const crow::request &req) {
        auto body = crow::json::load(req.body);
        if (!body)
          return crow::response(400);

        std::string username = body["username"].s();
        std::string password = body["password"].s();

        if (!session.register_user(username, password))
          return crow::response(409, "Usuario já existe");

        return crow::response(201, "Usuario criado");
      });

  CROW_ROUTE(app, "/login")
  ([] {
    crow::mustache::context ctx;
    ctx["title"] = "Login";
    return crow::mustache::load("login.mustache").render(ctx);
  });

  CROW_ROUTE(app, "/login")
      .methods(crow::HTTPMethod::POST)(
          [&session, &leaderboard](const crow::request &req) {
            auto body = crow::json::load(req.body);
            if (!body)
              return crow::response(400);

            if (!body.has("username") || !body.has("password")) {
              return crow::response(400, "Missing username or password.");
            }
            std::string username = body["username"].s();
            std::string password = body["password"].s();
            std::string token = session.login(username, password);

            if (token.empty()) {
              return crow::response(403, "Credenciais Invalídas");
            }
            crow::response res(200, "Login successful");
            res.set_header("Set-Cookie",
                           "session_id=" + token + "; HttpOnly; Path=/");
            return res;
          });

  CROW_ROUTE(app, "/logout")
  ([&session](const crow::request &req) {
    std::string token =
        extract_token_from_cookie(req.get_header_value("Cookie"));
    session.logout(token);

    crow::response res(302);
    res.set_header("Location", "/signup");
    res.set_header("Set-Cookie", "token=deleted; Path=/; Max-Age=0");
    return res;
  });

  CROW_ROUTE(app, "/leaderboard")
  ([&] {
    const auto &entries = leaderboard.top();

    crow::mustache::context ctx;
    ctx["title"] = "Leaderboard";

    crow::mustache::context::list users_list;
    for (const auto &[name, score] : entries) {
      crow::mustache::context row;
      row["name"] = name;
      row["score"] = std::to_string(score);
      users_list.push_back(std::move(row));
    }

    ctx["users"] = std::move(users_list);

    return crow::mustache::load("leaderboard.mustache").render(ctx);
  });

  auto register_secret_route = [&](const std::string &hash,
                                   const std::string &place) {
    app.route_dynamic("/" + hash)
        .methods(crow::HTTPMethod::GET)([&](const crow::request &req) {
          crow::mustache::context ctx;
          ctx["title"] = "QR Code";
          ctx["place"] = place;

          auto user = session.get_user(req);
          if (!user || user->empty()) {
            ctx["error"] =
                "Você precisa estar logado para acessar este QR code.";
            return crow::mustache::load("secret.mustache").render(ctx);
          }

          sqlite3_stmt *stmt = nullptr;
          const char *sql = "SELECT 1 FROM visits WHERE user_id = (SELECT id "
                            "FROM users WHERE username = ?) AND token = ?;";
          if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, user->c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 2, hash.c_str(), -1, SQLITE_TRANSIENT);
            bool visited = (sqlite3_step(stmt) == SQLITE_ROW);
            sqlite3_finalize(stmt);
            if (visited) {
              ctx["visited"] = true;
            } else {
              ctx["not_visited"] = true;
            }
            ctx["hash"] = hash;
          } else {
            ctx["error"] = "Erro ao verificar visita.";
          }

          return crow::mustache::load("secret.mustache").render(ctx);
        });

    app.route_dynamic("/" + hash + "/press")
        .methods(crow::HTTPMethod::POST)([&](const crow::request &req) {
          auto user = session.get_user(req);
          if (!user || user->empty()) {
            return crow::response(403, "Usuário não autenticado.");
          }

          const char *insert_sql =
              "INSERT OR IGNORE INTO visits (user_id, token) VALUES ((SELECT "
              "id FROM users WHERE username = ?), ?);";
          sqlite3_stmt *stmt = nullptr;
          if (sqlite3_prepare_v2(db, insert_sql, -1, &stmt, nullptr) ==
              SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, user->c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(stmt, 2, hash.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);

            leaderboard.submit(*user, 1);
            leaderboard.update();

            return crow::response(200, "Botão pressionado com sucesso.");
          } else {
            return crow::response(500, "Erro ao registrar visita.");
          }
        });
  };

  // registra rotas secretas
  for (const auto &[name, hash] : routes.get()) {
    register_secret_route(hash, name);
  }

  app.bindaddr("0.0.0.0").port(port).multithreaded().run();

  sqlite3_close(db);
}
