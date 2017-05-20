import std.typecons;
import core.time;
import vibe.core.core;
import std.stdio;
import std.process;
import vibe.http.server;
import vibe.http.router;
import vibe.http.client;
import vibe.core.log;
import vibe.core.args;
import vibe.core.concurrency;
import vibe.core.file;
import afldist.fuzzer;
import std.file;
import std.exception;
import std.format;
import std.path;
import vibe.stream.wrapper;
import std.algorithm : min;

enum Command {
  Stop = 1
}

struct Message
{
  Command cmd;
}

abstract class Fuzzer {
  private Task fuzzerTask, watcherTask;
  private DirectoryWatcher watcher;
  private {
    string aflBinary, testCasesFolder, findingsFolder, targetBinary, instanceFolder;
  }
  this(string aflBinary, string baseFolder, string targetBinary) {
    this.aflBinary = aflBinary;
    this.testCasesFolder = baseFolder ~ "/cases";
    this.findingsFolder = baseFolder ~ "/findings";
    this.targetBinary = targetBinary;
  }
  void syncFiles();
  void loadCases();
  private void startFuzzer(Flag!"isMaster" isMaster) {
    loadCases();
    fuzzerTask = runTask({
        string[] cmd = [aflBinary,"-i",testCasesFolder,"-o",findingsFolder,"-x",dirName(aflBinary)~"/dictionaries/js.dict"];
        if (isMaster) {
          cmd ~= ["-M","fuzzer01"];
        } else
          cmd ~= ["-S","fuzzer01"];
        cmd ~= [targetBinary,"--minify"];
        logInfo("Starting Fuzzer");
        auto fuzzer = pipeProcess(cmd, Redirect.stdin, cast(const(string[string]))null, cast(Config)0, dirName(aflBinary));
        bool fuzzing = true;
        auto wait = 600000.msecs;
        if (isMaster)
          wait = 5000.msecs;
        while (fuzzing) {
          if (!receiveTimeoutCompat(
                               wait,
                               (Message m){
                                 if (m.cmd == Command.Stop){
                                   fuzzing = false;
                                   kill(fuzzer.pid);
                                 }
                               }
                                    ))
            syncFiles();
          wait = 600000.msecs;
        }
      });
  }
  void stop() {
    fuzzerTask.send(Message(Command.Stop));
    exitEventLoop();
  }
}

class Server : Fuzzer {
  string baseFolder;
  this(string aflBinary, string baseFolder, string binary) {
    super(aflBinary, baseFolder, binary);
    startFuzzer(Yes.isMaster);
    this.baseFolder = baseFolder;
  }
  override void syncFiles() {
    void copy(string folder) {
      execute(["cp", "-rn", baseFolder~"/findings/fuzzer01/"~folder, baseFolder~"/findings/"]);
    }
    foreach(folder; ["crashes", "hangs", "queue"])
      copy(folder);
  }
  override void loadCases() {
  }
  void storeFindings(InputStream input) {
    deflate(input, baseFolder~"/findings");
  }
  void serve(OutputStream output, string folder) {
    inflate(output, baseFolder, folder);
  }
}

void deflate(InputStream input, string baseFolder) {
  auto tar = pipeProcess(["tar","-xjf","-"], Redirect.stdin | Redirect.stderr, cast(const(string[string]))null, cast(Config)0, baseFolder);
  ubyte[1024] buffer;
  while (!input.empty) {
    auto size = min(buffer.length,input.leastSize());
    input.read(buffer[0..size]);
    tar.stdin.rawWrite(buffer[0..size]);
  }
}

void inflate(OutputStream output, string baseFolder, string folder) {
  auto pipe = pipeProcess(["tar","-cjf","-",folder],
                          Redirect.stdout | Redirect.stderr, cast(const(string[string]))null, cast(Config)0, baseFolder);
  foreach(chunk; pipe.stdout.byChunk(1024))
    output.write(chunk);
}

class Client : Fuzzer {
  string url, baseFolder;
  this(string url, string aflBinary, string baseFolder, string binary) {
    super(aflBinary, baseFolder, binary);
    this.url = url;
    this.baseFolder = baseFolder;
    startFuzzer(No.isMaster);
  }
  override void syncFiles() {
    try {
      uploadHangs();
      uploadCrashes();
      uploadQueue();
      downloadQueue();
    } catch (Exception e) {
      stop();
    }
  }
  override void loadCases() {
    downloadTestCases();
  }
  auto uploadHangs() {
    return uploadFolder(baseFolder~"/findings/fuzzer01", "hangs");
  }
  auto uploadCrashes() {
    return uploadFolder(baseFolder~"/findings/fuzzer01", "crashes");
  }
  auto uploadQueue() {
    return uploadFolder(baseFolder~"/findings/fuzzer01", "queue");
  }
  auto downloadTestCases() {
    return downloadFolder(baseFolder, "cases");
  }
  auto downloadQueue() {
    return downloadFolder(baseFolder, "queue");
  }
  private auto uploadFolder(string baseFolder, string folder, string endpoint = "") {
    if (endpoint == "")
      endpoint = folder;
    requestHTTP(url~"/"~endpoint, (scope HTTPClientRequest req){
        req.method = HTTPMethod.PUT;
        inflate(req.bodyWriter, baseFolder, folder);
      },(scope HTTPClientResponse){
      });
  }
  private auto downloadFolder(string baseFolder, string endpoint) {
    import std.range : chunks;
    requestHTTP(url~"/"~endpoint, (scope HTTPClientRequest req){
      },(scope HTTPClientResponse res){
        scope(exit) res.dropBody();
        deflate(res.bodyReader, baseFolder);
      });
  }
}

struct Settings {
  bool isServer;
  bool isClient;
  string host = "http://localhost:8080";
  string bindTo = "0.0.0.0";
  string baseFolder;
  string aflBinary = "./afl-fuzz";
  string program;
  ushort port = 8080;
}

int main()
{
  Settings settings;
  settings.baseFolder = getcwd();
  readOption("p|port", &settings.port, "Port of master host to connect to (default: 8080)");
  readOption("s|server", &settings.isServer, "Starts up a master fuzzer");
  readOption("c|client", &settings.isClient, "Starts up a client fuzzer (default)");
  readOption("b|bind", &settings.bindTo, "bind to interface (default: 0.0.0.0)");
  readOption("f|folder", &settings.baseFolder, "folder to store results into (default: current directory)");
  readOption("h|host", &settings.host, "set master host (default: http://localhost:8080)");
  readOption("fuzzer", &settings.aflBinary, "set afl-fuzz binary (default: \"./afl-fuzz\")");
  try {
    settings.program = absolutePath(readRequiredOption!(string)("p|program", "program to fuzz"));
    if (!finalizeCommandLineOptions())
      return 0;
  } catch (Exception e) {
    printCommandLineHelp ();
    return 1;
  }
  settings.baseFolder = absolutePath(settings.baseFolder);
  settings.aflBinary = absolutePath(settings.aflBinary);
  if (settings.isClient) {
    return startClient(settings);
  } else if (settings.isServer) {
    return startServer(settings);
  }
  return 0;
}

int startClient(Settings settings) {
  auto client = new Client(settings.host, settings.aflBinary, settings.baseFolder, settings.program);
  auto r = runEventLoop();
  client.stop();
  return r;
}

int startServer(Settings settings) {
	auto serverSettings = new HTTPServerSettings;
	serverSettings.port = settings.port;
	serverSettings.bindAddresses = ["::1", settings.bindTo];

  logInfo("Starting Server");
  auto server = new Server(settings.aflBinary, settings.baseFolder, settings.program);
  auto router = new URLRouter;

	router.get("/stop", (HTTPServerRequest req, HTTPServerResponse res){ server.stop(); res.statusCode = 204; res.writeVoidBody(); });
	router.get("/queue", (HTTPServerRequest req, HTTPServerResponse res){ server.serve(res.bodyWriter, "./findings/queue"); });
	router.get("/crashes", (HTTPServerRequest req, HTTPServerResponse res){ server.serve(res.bodyWriter, "./findings/crashes"); });
	router.get("/hangs", (HTTPServerRequest req, HTTPServerResponse res){ server.serve(res.bodyWriter, "./findings/hangs"); });
	router.get("/cases", (HTTPServerRequest req, HTTPServerResponse res){ server.serve(res.bodyWriter, "./cases"); });
	router.put("/queue", (HTTPServerRequest req, HTTPServerResponse res){ server.storeFindings(req.bodyReader); res.statusCode = 204; res.writeVoidBody(); });
	router.put("/crashes", (HTTPServerRequest req, HTTPServerResponse res){ server.storeFindings(req.bodyReader); res.statusCode = 204; res.writeVoidBody(); });
	router.put("/hangs", (HTTPServerRequest req, HTTPServerResponse res){ server.storeFindings(req.bodyReader); res.statusCode = 204; res.writeVoidBody() ;});

	listenHTTP(serverSettings, router);
  logInfo("Listening on %s:%s", settings.bindTo, settings.port);
  auto r = runEventLoop();
  server.stop();
  return r;
}
