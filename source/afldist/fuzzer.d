module afldist.fuzzer;
import std.stdio;
import std.string;
import std.algorithm.searching;
import std.traits;
import std.range;
import std.conv;
import afldist.test;

struct Stats {
  size_t start_time;
  size_t last_update;
  size_t fuzzer_pid;
  size_t cycles_done;
  size_t execs_done;
  size_t execs_per_sec;
  size_t paths_total;
  size_t paths_favored;
  size_t paths_found;
  size_t paths_imported;
  size_t max_depth;
  size_t cur_path;
  size_t pending_favs;
  size_t pending_total;
  size_t variable_paths;
  string stability;
  string bitmap_cvg;
  size_t unique_crashes;
  size_t unique_hangs;
  size_t last_path;
  size_t last_crash;
  size_t last_hang;
  size_t execs_since_crash;
  size_t exec_timeout;
  string afl_banner;
  string afl_version;
  string command_line;
}

Stats parseStats(Lines)(Lines input)
  if (isInputRange!Lines && is(ElementType!Lines == string ))
{
  Stats s;
  foreach(line; input) {
    auto split = line.findSplitBefore(":");
    if (split[1].empty)
      continue;
    auto key = split[0].stripRight;
    foreach(name; FieldNameTuple!Stats) {
      if (key != name)
        continue;
      auto value = split[1].drop(1).stripLeft;
      alias MemberType = typeof(__traits(getMember, s, name));
      try {
        __traits(getMember, s, name) = value.to!MemberType;
      } catch (Exception e) { }
    }
  }
  return s;
}

Stats parseStats(string filename)
{
  import std.algorithm.iteration;
  import std.file;
  string content = readText(filename);
  return parseStats(content.lineSplitter());
}

@("parseStats")
unittest {
  parseStats(["start_time : 23452345", "paths_found     :      3452345"]).shouldEqual(Stats(23452345, 0, 0, 0, 0, 0, 0, 0, 3452345, 0, 0, 0, 0, 0, 0, "", "", 0, 0, 0, 0, 0, 0, 0, "", "", ""));
}
