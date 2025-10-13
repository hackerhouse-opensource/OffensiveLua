// OffensiveLuaEmbedded.cpp : Advanced LuaJIT script debugger utility.
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

extern "C" {
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
}

/*
Legacy minimal embedding example for quick reference:

int main(int argc, char* argv[])
{
	lua_State* L;
	int error = 0;
	if (argc < 2) {
		printf("No script provided\r\n");
		return EXIT_FAILURE;
	}
	L = luaL_newstate();
	if (L) {
		luaL_openlibs(L);
		luaL_loadfile(L, argv[1]);
		error = lua_pcall(L, 0, 0, 0);
		if (error) {
			fprintf(stderr, "%s", lua_tostring(L, -1));
			lua_pop(L, 1);
		}
		lua_close(L);
	}
	return EXIT_SUCCESS;
}
*/

// Linked libraries.
#pragma comment(lib, "lua51.lib")

namespace
{
constexpr int kInstructionSampleInterval = 1;
constexpr const char* kProgramTitle = "Offensive LuaJIT Debugger";
static int gDebuggerRegistryKey = 0;

struct DebugConfig
{
	bool interactive = false;
	bool dumpBytecode = true;
	bool traceLines = false;
	bool countInstructions = true;
	bool printMemorySummary = true;
	std::string scriptPath;
	std::vector<std::string> scriptArgs;
};

class ScopedStackGuard
{
public:
	ScopedStackGuard(lua_State* state, int expectedTop) noexcept
		: L(state), originalTop(expectedTop)
	{
	}

	ScopedStackGuard(const ScopedStackGuard&) = delete;
	ScopedStackGuard& operator=(const ScopedStackGuard&) = delete;

	~ScopedStackGuard()
	{
		if (L && lua_gettop(L) != originalTop)
		{
			lua_settop(L, originalTop);
		}
	}

private:
	lua_State* L;
	int originalTop;
};

[[nodiscard]] std::string toLowerCopy(std::string value)
{
	std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
	return value;
}

[[nodiscard]] std::string trim(const std::string& value)
{
	const auto start = value.find_first_not_of(" \t\r\n");
	if (start == std::string::npos)
	{
		return {};
	}
	const auto end = value.find_last_not_of(" \t\r\n");
	return value.substr(start, end - start + 1);
}

[[nodiscard]] std::string join(const std::vector<std::string>& parts, std::size_t startIndex = 0)
{
	if (startIndex >= parts.size())
	{
		return {};
	}

	std::ostringstream oss;
	for (std::size_t i = startIndex; i < parts.size(); ++i)
	{
		if (i > startIndex)
		{
			oss << ' ';
		}
		oss << parts[i];
	}
	return oss.str();
}

[[nodiscard]] std::optional<std::filesystem::path> canonicalizePath(const std::string& raw)
{
	if (raw.empty())
	{
		return std::nullopt;
	}

	std::filesystem::path pathCandidate(raw);
	if (!pathCandidate.is_absolute())
	{
		std::error_code ec;
		pathCandidate = std::filesystem::absolute(pathCandidate, ec);
		if (ec)
		{
			return std::nullopt;
		}
	}

	std::error_code ec;
	auto canonicalPath = std::filesystem::weakly_canonical(pathCandidate, ec);
	if (ec)
	{
		return std::nullopt;
	}
	return canonicalPath;
}

[[nodiscard]] std::string valueToString(lua_State* L, int index)
{
	const int type = lua_type(L, index);
	switch (type)
	{
	case LUA_TNIL:
		return "nil";
	case LUA_TBOOLEAN:
		return lua_toboolean(L, index) ? "true" : "false";
	case LUA_TNUMBER:
	{
		std::ostringstream oss;
		oss << std::setprecision(std::numeric_limits<double>::digits10 + 1) << lua_tonumber(L, index);
		return oss.str();
	}
	case LUA_TSTRING:
	{
		std::ostringstream oss;
		size_t len = 0;
		const char* str = lua_tolstring(L, index, &len);
		oss << '"';
		for (size_t i = 0; i < len; ++i)
		{
			const unsigned char ch = static_cast<unsigned char>(str[i]);
			if (ch == '\n')
			{
				oss << "\\n";
			}
			else if (ch == '\r')
			{
				oss << "\\r";
			}
			else if (ch == '\t')
			{
				oss << "\\t";
			}
			else if (ch == '\\' || ch == '"')
			{
				oss << '\\' << ch;
			}
			else if (std::isprint(ch) != 0)
			{
				oss << ch;
			}
			else
			{
				oss << "\\x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(ch) << std::dec << std::setfill(' ');
			}
		}
		oss << '"';
		return oss.str();
	}
	case LUA_TTABLE:
	{
		std::ostringstream oss;
		oss << "table: " << lua_topointer(L, index);
		return oss.str();
	}
	case LUA_TFUNCTION:
	{
		std::ostringstream oss;
		oss << "function: " << lua_topointer(L, index);
		return oss.str();
	}
	case LUA_TUSERDATA:
	{
		std::ostringstream oss;
		oss << "userdata: " << lua_touserdata(L, index);
		return oss.str();
	}
	case LUA_TLIGHTUSERDATA:
	{
		std::ostringstream oss;
		oss << "lightuserdata: " << lua_touserdata(L, index);
		return oss.str();
	}
	case LUA_TTHREAD:
		return "thread";
	default:
		return "<unknown>";
	}
}

class LuaDebugger
{
public:
	LuaDebugger() = default;

	void initialize(lua_State* state, const DebugConfig& cfg)
	{
		L = state;
		config = cfg;
		registerSelf();
		if (config.interactive)
		{
			runMode = RunMode::Step;
			std::cout << "[info] Interactive debugging enabled. Type 'help' for commands." << std::endl;
		}
		else
		{
			runMode = RunMode::Continue;
		}
	}

	void prepareChunkMetadata(int functionIndex, const std::string& chunkPath)
	{
		(void)functionIndex;
		primaryChunkPath = chunkPath;
	}

	void beforeExecution()
	{
		if (!L)
		{
			return;
		}

		hookMask = LUA_MASKLINE | LUA_MASKCALL | LUA_MASKRET;
		hookCount = 0;
		if (config.countInstructions)
		{
			hookMask |= LUA_MASKCOUNT;
			hookCount = kInstructionSampleInterval;
		}

		lua_sethook(L, &LuaDebugger::hookDispatch, hookMask, hookCount);
		hooksActive = true;
	}

	void afterExecution(int status)
	{
		if (hooksActive && L)
		{
			lua_sethook(L, nullptr, 0, 0);
			hooksActive = false;
		}

		if (status != LUA_OK && L)
		{
			const char* errorMessage = lua_tostring(L, -1);
			if (errorMessage != nullptr)
			{
				std::cerr << "[error] " << errorMessage << std::endl;
			}
		}

		if (config.printMemorySummary && L)
		{
			printMemoryUsage();
		}

		printExecutionSummary();
	}

	void dumpBytecodeFromStackIndex(int index, const std::string& description)
	{
		if (!config.dumpBytecode || !L)
		{
			return;
		}

		ScopedHookPause pause(*this);

		const int absoluteIndex = (index < 0) ? lua_gettop(L) + index + 1 : index;
		if (absoluteIndex <= 0 || absoluteIndex > lua_gettop(L))
		{
			std::cerr << "[warn] Unable to dump bytecode for " << description << ": invalid stack index." << std::endl;
			return;
		}

		lua_pushvalue(L, absoluteIndex);
		ScopedStackGuard stackGuard(L, lua_gettop(L));

		std::vector<unsigned char> buffer;
		const auto writer = [](lua_State*, const void* p, size_t sz, void* ud) -> int {
			auto* data = static_cast<std::vector<unsigned char>*>(ud);
			const auto* bytes = static_cast<const unsigned char*>(p);
			data->insert(data->end(), bytes, bytes + sz);
			return 0;
		};

		if (lua_dump(L, writer, &buffer) != 0)
		{
			std::cerr << "[warn] Failed to dump bytecode for " << description << std::endl;
			return;
		}

		std::cout << "[bytecode] " << description << " (" << buffer.size() << " bytes)" << std::endl;
		constexpr std::size_t bytesPerLine = 16;
		std::size_t offset = 0;
		while (offset < buffer.size())
		{
			std::cout << "  " << std::setw(6) << std::setfill('0') << std::hex << offset << std::dec << std::setfill(' ') << "  ";
			std::size_t lineBytes = std::min(bytesPerLine, buffer.size() - offset);
			for (std::size_t i = 0; i < lineBytes; ++i)
			{
				std::cout << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(buffer[offset + i]) << std::dec << std::setfill(' ');
				if (i + 1 != lineBytes)
				{
					std::cout << ' ';
				}
			}
			std::cout << std::endl;
			offset += lineBytes;
		}
	}

private:
	enum class RunMode
	{
		Continue,
		Step
	};

	enum class CommandResult
	{
		StayPaused,
		Resume,
		Abort
	};

	class ScopedHookPause
	{
	public:
		explicit ScopedHookPause(LuaDebugger& dbg)
			: debugger(dbg), active(false), priorHook(nullptr)
		{
			if (!debugger.L)
			{
				return;
			}

			priorHook = lua_gethook(debugger.L);
			priorMask = lua_gethookmask(debugger.L);
			priorCount = lua_gethookcount(debugger.L);
			lua_sethook(debugger.L, nullptr, 0, 0);
			active = true;
		}

		ScopedHookPause(const ScopedHookPause&) = delete;
		ScopedHookPause& operator=(const ScopedHookPause&) = delete;

		~ScopedHookPause()
		{
			if (active && debugger.L)
			{
				lua_sethook(debugger.L, priorHook, priorMask, priorCount);
			}
		}

	private:
		LuaDebugger& debugger;
		bool active;
		lua_Hook priorHook;
		int priorMask;
		int priorCount;
	};

	struct SourceLocation
	{
		std::string displayPath;
		std::optional<std::filesystem::path> canonicalPath;
		int line = 0;
	};

	lua_State* L = nullptr;
	DebugConfig config{};
	bool hooksActive = false;
	int hookMask = 0;
	int hookCount = 0;
	RunMode runMode = RunMode::Continue;
	bool abortRequested = false;
	uint64_t totalInstructionCount = 0;
	uint64_t totalLineEvents = 0;
	int currentDepth = 0;
	std::string primaryChunkPath;
	std::map<std::string, std::set<int>> breakpoints;
	std::map<std::string, std::map<int, uint64_t>> lineHitCount;
	std::unordered_map<std::string, std::vector<std::string>> sourceCache;

	static void hookDispatch(lua_State* state, lua_Debug* ar)
	{
		LuaDebugger* self = nullptr;

		lua_pushlightuserdata(state, &gDebuggerRegistryKey);
		lua_gettable(state, LUA_REGISTRYINDEX);
		if (lua_islightuserdata(state, -1) != 0)
		{
			self = static_cast<LuaDebugger*>(lua_touserdata(state, -1));
		}
		lua_pop(state, 1);

		if (self)
		{
			self->handleHook(state, ar);
		}
	}

	void registerSelf()
	{
		if (!L)
		{
			return;
		}

		lua_pushlightuserdata(L, &gDebuggerRegistryKey);
		lua_pushlightuserdata(L, this);
		lua_settable(L, LUA_REGISTRYINDEX);
	}

	void handleHook(lua_State* state, lua_Debug* ar)
	{
		if (abortRequested)
		{
			luaL_error(state, "Execution aborted by debugger");
			return;
		}

		switch (ar->event)
		{
		case LUA_HOOKCALL:
			++currentDepth;
			break;
		case LUA_HOOKRET:
		case LUA_HOOKTAILRET:
			if (currentDepth > 0)
			{
				--currentDepth;
			}
			break;
		case LUA_HOOKCOUNT:
			totalInstructionCount += static_cast<uint64_t>(kInstructionSampleInterval);
			break;
		case LUA_HOOKLINE:
			handleLineEvent(state, ar);
			break;
		default:
			break;
		}
	}

	void handleLineEvent(lua_State* state, lua_Debug* ar)
	{
		lua_getinfo(state, "Sln", ar);
		const auto location = extractLocation(*ar);
		if (!location.displayPath.empty())
		{
			lineHitCount[location.displayPath][location.line] += 1;
		}

		++totalLineEvents;

		if (config.traceLines)
		{
			printLineTrace(location);
		}

		if (!shouldPauseAt(location))
		{
			return;
		}

		printCurrentLine(location);
		enterInteractiveShell(ar, location);
	}

	[[nodiscard]] bool shouldPauseAt(const SourceLocation& location) const
	{
		if (!config.interactive)
		{
			auto it = breakpoints.find(location.displayPath);
			return it != breakpoints.end() && it->second.count(location.line) > 0;
		}

		if (runMode == RunMode::Step)
		{
			return true;
		}

		const auto it = breakpoints.find(location.displayPath);
		return it != breakpoints.end() && it->second.count(location.line) > 0;
	}

	void enterInteractiveShell(lua_Debug* ar, const SourceLocation& location)
	{
		while (true)
		{
			std::cout << "(lua-debug) " << std::flush;
			std::string line;
			if (!std::getline(std::cin, line))
			{
				runMode = RunMode::Continue;
				return;
			}

			const auto trimmed = trim(line);
			if (trimmed.empty())
			{
				continue;
			}

			const auto parts = splitCommand(trimmed);
			if (parts.empty())
			{
				continue;
			}

			const auto command = toLowerCopy(parts[0]);
			const auto result = executeCommand(command, parts, ar, location);

			if (result == CommandResult::Abort)
			{
				abortRequested = true;
				luaL_error(L, "Execution aborted by debugger");
				return;
			}

			if (result == CommandResult::Resume)
			{
				return;
			}
		}
	}

	[[nodiscard]] static std::vector<std::string> splitCommand(const std::string& line)
	{
		std::vector<std::string> tokens;
		std::istringstream iss(line);
		std::string token;
		while (iss >> token)
		{
			tokens.push_back(token);
		}
		return tokens;
	}

	[[nodiscard]] CommandResult executeCommand(const std::string& command,
											  const std::vector<std::string>& parts,
											  lua_Debug* ar,
											  const SourceLocation& location)
	{
		if (command == "help" || command == "h")
		{
			printHelp();
			return CommandResult::StayPaused;
		}

		if (command == "continue" || command == "c")
		{
			runMode = RunMode::Continue;
			return CommandResult::Resume;
		}

		if (command == "step" || command == "s")
		{
			runMode = RunMode::Step;
			return CommandResult::Resume;
		}

		if (command == "break" || command == "b")
		{
			handleBreakCommand(parts, location);
			return CommandResult::StayPaused;
		}

		if (command == "clear")
		{
			handleClearBreakpoint(parts, location);
			return CommandResult::StayPaused;
		}

		if (command == "breakpoints" || command == "bp")
		{
			listBreakpoints();
			return CommandResult::StayPaused;
		}

		if (command == "print" || command == "p")
		{
			runInspectExpression(parts, true);
			return CommandResult::StayPaused;
		}

		if (command == "eval" || command == "exec" || command == "x")
		{
			runInspectExpression(parts, false);
			return CommandResult::StayPaused;
		}

		if (command == "locals" || command == "l")
		{
			listLocals(ar);
			return CommandResult::StayPaused;
		}

		if (command == "stack" || command == "bt")
		{
			printStackTrace();
			return CommandResult::StayPaused;
		}

		if (command == "upvalues" || command == "up")
		{
			listUpvalues(ar);
			return CommandResult::StayPaused;
		}

		if (command == "globals" || command == "g")
		{
			listGlobals(parts);
			return CommandResult::StayPaused;
		}

		if (command == "memory" || command == "mem")
		{
			printMemoryUsage();
			return CommandResult::StayPaused;
		}

		if (command == "stats")
		{
			printExecutionSummary();
			return CommandResult::StayPaused;
		}

		if (command == "bytecode" || command == "bc")
		{
			dumpCurrentFunctionBytecode(ar);
			return CommandResult::StayPaused;
		}

		if (command == "quit" || command == "q")
		{
			return CommandResult::Abort;
		}

		std::cout << "[warn] Unknown command. Type 'help' to see available commands." << std::endl;
		return CommandResult::StayPaused;
	}

	void dumpCurrentFunctionBytecode(lua_Debug* ar)
	{
		ScopedHookPause pause(*this);
		lua_getinfo(L, "f", ar);
		ScopedStackGuard guard(L, lua_gettop(L));
		if (lua_isfunction(L, -1) == 0)
		{
			std::cout << "[warn] Unable to resolve current function for bytecode dump." << std::endl;
			return;
		}
		dumpBytecodeFromStackIndex(-1, "current-function");
	}

	void printHelp() const
	{
		std::cout << "Commands:" << std::endl;
		std::cout << "  help (h)            Show this help." << std::endl;
		std::cout << "  continue (c)        Resume execution until next breakpoint." << std::endl;
		std::cout << "  step (s)            Step one Lua line." << std::endl;
		std::cout << "  break|b [file:]line Set a breakpoint." << std::endl;
		std::cout << "  clear [file:]line   Remove a breakpoint." << std::endl;
		std::cout << "  breakpoints (bp)    List defined breakpoints." << std::endl;
		std::cout << "  print|p <expr>      Evaluate expression and print results." << std::endl;
		std::cout << "  eval|exec|x <code>  Execute Lua chunk in current context." << std::endl;
		std::cout << "  locals (l)          List local variables." << std::endl;
		std::cout << "  upvalues (up)       List upvalues for current function." << std::endl;
		std::cout << "  globals (g) [pat]   List globals optionally filtered." << std::endl;
		std::cout << "  stack (bt)          Show current call stack." << std::endl;
		std::cout << "  memory (mem)        Display memory usage statistics." << std::endl;
		std::cout << "  stats               Show execution statistics." << std::endl;
		std::cout << "  bytecode (bc)       Dump bytecode for current function." << std::endl;
		std::cout << "  quit (q)            Abort execution." << std::endl;
	}

	void handleBreakCommand(const std::vector<std::string>& parts, const SourceLocation& currentLocation)
	{
		if (parts.size() < 2)
		{
			std::cout << "[warn] Usage: break [file:]line" << std::endl;
			return;
		}

		const auto target = parts[1];
		std::string fileComponent;
		std::string lineComponent;
		const auto separatorPos = target.find(':');
		if (separatorPos == std::string::npos)
		{
			fileComponent = currentLocation.displayPath;
			lineComponent = target;
		}
		else
		{
			fileComponent = target.substr(0, separatorPos);
			lineComponent = target.substr(separatorPos + 1);
		}

		int lineValue = 0;
		try
		{
			lineValue = std::stoi(lineComponent);
		}
		catch (...)
		{
			std::cout << "[warn] Invalid line number." << std::endl;
			return;
		}

		if (lineValue <= 0)
		{
			std::cout << "[warn] Line numbers must be positive." << std::endl;
			return;
		}

		auto normalizedFile = fileComponent;
		if (!normalizedFile.empty())
		{
			normalizedFile = normalizedFile == currentLocation.displayPath
								  ? currentLocation.displayPath
								  : resolveDisplayPath(normalizedFile);
		}

		if (normalizedFile.empty())
		{
			std::cout << "[warn] Unable to resolve target file." << std::endl;
			return;
		}

		breakpoints[normalizedFile].insert(lineValue);
		std::cout << "[info] Breakpoint added at " << normalizedFile << ':' << lineValue << std::endl;
	}

	void handleClearBreakpoint(const std::vector<std::string>& parts, const SourceLocation& currentLocation)
	{
		if (parts.size() < 2)
		{
			std::cout << "[warn] Usage: clear [file:]line" << std::endl;
			return;
		}

		const auto target = parts[1];
		std::string fileComponent;
		std::string lineComponent;
		const auto separatorPos = target.find(':');
		if (separatorPos == std::string::npos)
		{
			fileComponent = currentLocation.displayPath;
			lineComponent = target;
		}
		else
		{
			fileComponent = target.substr(0, separatorPos);
			lineComponent = target.substr(separatorPos + 1);
		}

		int lineValue = 0;
		try
		{
			lineValue = std::stoi(lineComponent);
		}
		catch (...)
		{
			std::cout << "[warn] Invalid line number." << std::endl;
			return;
		}

		auto normalizedFile = fileComponent;
		if (!normalizedFile.empty())
		{
			normalizedFile = normalizedFile == currentLocation.displayPath
								  ? currentLocation.displayPath
								  : resolveDisplayPath(normalizedFile);
		}

		if (normalizedFile.empty())
		{
			std::cout << "[warn] Unable to resolve target file." << std::endl;
			return;
		}

		auto breakpointIt = breakpoints.find(normalizedFile);
		if (breakpointIt == breakpoints.end())
		{
			std::cout << "[warn] No breakpoint defined for " << normalizedFile << std::endl;
			return;
		}

		const auto removed = breakpointIt->second.erase(lineValue);
		if (removed == 0)
		{
			std::cout << "[warn] No breakpoint at line " << lineValue << " in " << normalizedFile << std::endl;
			return;
		}

		if (breakpointIt->second.empty())
		{
			breakpoints.erase(breakpointIt);
		}

		std::cout << "[info] Breakpoint removed from " << normalizedFile << ':' << lineValue << std::endl;
	}

	void listBreakpoints() const
	{
		if (breakpoints.empty())
		{
			std::cout << "[info] No breakpoints defined." << std::endl;
			return;
		}

		std::cout << "Breakpoints:" << std::endl;
		for (const auto& [file, lines] : breakpoints)
		{
			for (const int line : lines)
			{
				std::cout << "  " << file << ':' << line << std::endl;
			}
		}
	}

	void runInspectExpression(const std::vector<std::string>& parts, bool withReturn)
	{
		if (parts.size() < 2)
		{
			std::cout << "[warn] Missing expression." << std::endl;
			return;
		}

		const std::string expression = join(parts, 1);
		ScopedHookPause pause(*this);
		const int originalTop = lua_gettop(L);
		ScopedStackGuard guard(L, originalTop);

		std::string wrappedCode;
		if (withReturn)
		{
			wrappedCode = "return " + expression;
		}
		else
		{
			wrappedCode = expression;
		}

		if (luaL_loadstring(L, wrappedCode.c_str()) != LUA_OK)
		{
			const char* errorMessage = lua_tostring(L, -1);
			std::cout << "[error] " << (errorMessage ? errorMessage : "failed to load expression") << std::endl;
			return;
		}

		if (lua_pcall(L, 0, LUA_MULTRET, 0) != LUA_OK)
		{
			const char* errorMessage = lua_tostring(L, -1);
			std::cout << "[error] " << (errorMessage ? errorMessage : "execution failed") << std::endl;
			return;
		}

		const int resultCount = lua_gettop(L) - originalTop;
		if (withReturn)
		{
			if (resultCount == 0)
			{
				std::cout << "[info] (no results)" << std::endl;
				return;
			}

			for (int i = 1; i <= resultCount; ++i)
			{
				std::cout << "[result] " << valueToString(L, originalTop + i) << std::endl;
			}
		}
		else
		{
			std::cout << "[info] Expression executed." << std::endl;
		}
	}

	void listLocals(lua_Debug* ar)
	{
		ScopedHookPause pause(*this);
		int index = 1;
		std::cout << "Locals:" << std::endl;
		bool any = false;
		const int originalTop = lua_gettop(L);
		while (true)
		{
			const char* name = lua_getlocal(L, ar, index++);
			if (name == nullptr)
			{
				break;
			}
			any = true;
			std::cout << "  " << name << " = " << valueToString(L, -1) << std::endl;
			lua_pop(L, 1);
		}
		if (!any)
		{
			std::cout << "  (none)" << std::endl;
		}
		lua_settop(L, originalTop);
	}

	void listUpvalues(lua_Debug* ar)
	{
		ScopedHookPause pause(*this);
		lua_getinfo(L, "f", ar);
		ScopedStackGuard guard(L, lua_gettop(L));
		if (lua_isfunction(L, -1) == 0)
		{
			std::cout << "[warn] Unable to access upvalues." << std::endl;
			return;
		}

		std::cout << "Upvalues:" << std::endl;
		bool any = false;
		for (int idx = 1;; ++idx)
		{
			const char* name = lua_getupvalue(L, -1, idx);
			if (name == nullptr)
			{
				break;
			}
			any = true;
			std::cout << "  " << name << " = " << valueToString(L, -1) << std::endl;
			lua_pop(L, 1);
		}

		if (!any)
		{
			std::cout << "  (none)" << std::endl;
		}
	}

	void listGlobals(const std::vector<std::string>& parts)
	{
		ScopedHookPause pause(*this);
		std::string filter;
		if (parts.size() > 1)
		{
			filter = parts[1];
		}

		auto matchesFilter = [&filter](const std::string& name) {
			if (filter.empty())
			{
				return true;
			}
			return name.find(filter) != std::string::npos;
		};

		const int originalTop = lua_gettop(L);
#if LUA_VERSION_NUM >= 502
		lua_pushglobaltable(L);
#else
		lua_pushvalue(L, LUA_GLOBALSINDEX);
#endif

		std::cout << "Globals:" << std::endl;
		bool any = false;
		lua_pushnil(L);
		while (lua_next(L, -2) != 0)
		{
			const char* key = lua_tostring(L, -2);
			if (key != nullptr && matchesFilter(key))
			{
				any = true;
				std::cout << "  " << key << " = " << valueToString(L, -1) << std::endl;
			}
			lua_pop(L, 1);
		}

		if (!any)
		{
			std::cout << "  (none)" << std::endl;
		}

		lua_settop(L, originalTop);
	}

	void printStackTrace()
	{
		ScopedHookPause pause(*this);
		std::cout << "Stack trace:" << std::endl;
		lua_Debug info{};
		for (int level = 0; lua_getstack(L, level, &info) != 0; ++level)
		{
			lua_getinfo(L, "Sln", &info);
			std::string functionName = info.name ? info.name : "<anonymous>";
			const auto location = extractLocation(info);
			std::cout << "  [" << level << "] " << functionName;
			if (!location.displayPath.empty())
			{
				std::cout << " at " << location.displayPath << ':' << location.line;
			}
			std::cout << std::endl;
		}
	}

	void printMemoryUsage() const
	{
		if (!L)
		{
			return;
		}

		const long kb = lua_gc(L, LUA_GCCOUNT, 0);
		const long remainder = lua_gc(L, LUA_GCCOUNTB, 0);
		const double bytes = static_cast<double>(kb) * 1024.0 + static_cast<double>(remainder);
		std::cout << std::fixed << std::setprecision(2);
		std::cout << "[memory] total: " << bytes / 1024.0 << " KiB" << std::endl;
		std::cout.unsetf(std::ios::floatfield);
	}

	void printExecutionSummary()
	{
		std::cout << "[summary] Instruction samples: " << totalInstructionCount << ", line events: " << totalLineEvents << std::endl;
		if (lineHitCount.empty())
		{
			return;
		}

		std::cout << "[summary] Hot lines:" << std::endl;
		struct LineStat
		{
			std::string file;
			int line;
			uint64_t hits;
		};

		std::vector<LineStat> hotLines;
		for (const auto& [file, lines] : lineHitCount)
		{
			for (const auto& [line, hits] : lines)
			{
				hotLines.push_back({file, line, hits});
			}
		}

		constexpr std::size_t maxEntries = 10;
		std::partial_sort(hotLines.begin(), hotLines.begin() + std::min(hotLines.size(), maxEntries), hotLines.end(),
						  [](const LineStat& a, const LineStat& b) { return a.hits > b.hits; });

		const std::size_t count = std::min(hotLines.size(), maxEntries);
		for (std::size_t i = 0; i < count; ++i)
		{
			const auto& entry = hotLines[i];
			std::cout << "  " << std::setw(6) << entry.hits << " hits  " << entry.file << ':' << entry.line << std::endl;
		}
	}

	void printLineTrace(const SourceLocation& location)
	{
		std::cout << "[trace] " << location.displayPath << ':' << location.line;
		const auto lineContent = getLineContent(location);
		if (lineContent.has_value())
		{
			std::cout << " | " << *lineContent;
		}
		std::cout << std::endl;
	}

	void printCurrentLine(const SourceLocation& location)
	{
		std::cout << "[pause] " << location.displayPath << ':' << location.line;
		const auto lineContent = getLineContent(location);
		if (lineContent.has_value())
		{
			std::cout << " | " << *lineContent;
		}
		std::cout << std::endl;
	}

	[[nodiscard]] SourceLocation extractLocation(const lua_Debug& info)
	{
		SourceLocation result;
		if (info.source != nullptr)
		{
			if (info.source[0] == '@')
			{
				const std::string sourcePath = info.source + 1;
				const auto canonical = canonicalizePath(sourcePath);
				if (canonical.has_value())
				{
					result.canonicalPath = canonical;
					result.displayPath = canonical->string();
				}
				else
				{
					result.displayPath = sourcePath;
				}
			}
			else
			{
				result.displayPath = info.source;
			}
		}

		result.line = info.currentline;
		if (result.displayPath.empty() && !primaryChunkPath.empty())
		{
			result.displayPath = primaryChunkPath;
		}

		return result;
	}

	[[nodiscard]] std::optional<std::string> getLineContent(const SourceLocation& location)
	{
		if (location.line <= 0 || location.displayPath.empty())
		{
			return std::nullopt;
		}

		auto& cacheEntry = sourceCache[location.displayPath];
		if (cacheEntry.empty())
		{
			std::ifstream fileStream(location.displayPath);
			if (!fileStream)
			{
				return std::nullopt;
			}

			std::string line;
			while (std::getline(fileStream, line))
			{
				cacheEntry.push_back(line);
			}
		}

		const int index = location.line - 1;
		if (index < 0 || static_cast<std::size_t>(index) >= cacheEntry.size())
		{
			return std::nullopt;
		}

		return cacheEntry[static_cast<std::size_t>(index)];
	}

	[[nodiscard]] std::string resolveDisplayPath(const std::string& candidate)
	{
		const auto canonical = canonicalizePath(candidate);
		if (canonical.has_value())
		{
			return canonical->string();
		}
		return candidate;
	}
};

class LuaApplication
{
public:
	LuaApplication() = default;

	int run(const DebugConfig& cfg)
	{
		config = cfg;
		luaState.reset(luaL_newstate());
		if (!luaState)
		{
			std::cerr << "[fatal] Unable to allocate Lua state." << std::endl;
			return EXIT_FAILURE;
		}

		luaL_openlibs(luaState.get());

		debugger.initialize(luaState.get(), config);

		if (!loadScript())
		{
			return EXIT_FAILURE;
		}

		if (config.dumpBytecode)
		{
			debugger.dumpBytecodeFromStackIndex(-1, config.scriptPath);
		}

		setupArguments();

		debugger.beforeExecution();

		const int status = lua_pcall(luaState.get(), 0, LUA_MULTRET, 0);
		debugger.afterExecution(status);

		return status == LUA_OK ? EXIT_SUCCESS : EXIT_FAILURE;
	}

private:
	struct LuaStateDeleter
	{
		void operator()(lua_State* state) const noexcept
		{
			if (state)
			{
				lua_close(state);
			}
		}
	};

	DebugConfig config{};
	std::unique_ptr<lua_State, LuaStateDeleter> luaState;
	LuaDebugger debugger;

	bool loadScript()
	{
		const int status = luaL_loadfile(luaState.get(), config.scriptPath.c_str());
		if (status != LUA_OK)
		{
			const char* message = lua_tostring(luaState.get(), -1);
			std::cerr << "[error] " << (message ? message : "failed to load script") << std::endl;
			return false;
		}

		debugger.prepareChunkMetadata(-1, config.scriptPath);
		return true;
	}

	void setupArguments()
	{
		const int originalTop = lua_gettop(luaState.get());
		ScopedStackGuard guard(luaState.get(), originalTop);

#if LUA_VERSION_NUM >= 502
		lua_pushglobaltable(luaState.get());
#else
		lua_pushvalue(luaState.get(), LUA_GLOBALSINDEX);
#endif

		lua_newtable(luaState.get());
		int argIndex = 1;
		for (const auto& arg : config.scriptArgs)
		{
			lua_pushinteger(luaState.get(), argIndex++);
			lua_pushlstring(luaState.get(), arg.c_str(), arg.size());
			lua_settable(luaState.get(), -3);
		}

		lua_setfield(luaState.get(), -2, "arg");

		lua_pop(luaState.get(), 1);
	}
};

void printUsage()
{
	std::cout << kProgramTitle << std::endl;
	std::cout << "Usage: luadebug [options] <script.lua> [args...]" << std::endl;
	std::cout << "Options:" << std::endl;
	std::cout << "  --interactive, -i      Enable interactive debugging mode." << std::endl;
	std::cout << "  --dump-bytecode, -b    Dump chunk bytecode (default)." << std::endl;
	std::cout << "  --no-bytecode          Disable bytecode dump." << std::endl;
	std::cout << "  --trace-lines, -t      Log every executed line." << std::endl;
	std::cout << "  --count, -c            Track instruction samples (default)." << std::endl;
	std::cout << "  --no-count             Disable instruction sampling." << std::endl;
	std::cout << "  --memory, -m           Print memory summary after execution (default)." << std::endl;
	std::cout << "  --no-memory            Skip memory summary." << std::endl;
	std::cout << "  --help, -h             Show this help message." << std::endl;
}

std::optional<DebugConfig> parseArguments(int argc, char* argv[])
{
	if (argc < 2)
	{
		printUsage();
		return std::nullopt;
	}

	DebugConfig config;
	int scriptIndex = -1;
	for (int i = 1; i < argc; ++i)
	{
		const std::string arg = argv[i];
		if (arg == "--help" || arg == "-h")
		{
			printUsage();
			return std::nullopt;
		}

		if (arg == "--interactive" || arg == "-i")
		{
			config.interactive = true;
			continue;
		}

		if (arg == "--dump-bytecode" || arg == "-b")
		{
			config.dumpBytecode = true;
			continue;
		}

		if (arg == "--no-bytecode")
		{
			config.dumpBytecode = false;
			continue;
		}

		if (arg == "--trace-lines" || arg == "-t")
		{
			config.traceLines = true;
			continue;
		}

		if (arg == "--count" || arg == "-c")
		{
			config.countInstructions = true;
			continue;
		}

		if (arg == "--no-count")
		{
			config.countInstructions = false;
			continue;
		}

		if (arg == "--memory" || arg == "-m")
		{
			config.printMemorySummary = true;
			continue;
		}

		if (arg == "--no-memory")
		{
			config.printMemorySummary = false;
			continue;
		}

		if (arg == "--")
		{
			scriptIndex = i + 1;
			break;
		}

		if (!arg.empty() && arg.front() == '-')
		{
			std::cerr << "[error] Unknown option: " << arg << std::endl;
			return std::nullopt;
		}

		scriptIndex = i;
		break;
	}

	if (scriptIndex < 0 || scriptIndex >= argc)
	{
		std::cerr << "[error] Missing Lua script path." << std::endl;
		return std::nullopt;
	}

	config.scriptPath = argv[scriptIndex];

	for (int i = scriptIndex + 1; i < argc; ++i)
	{
		config.scriptArgs.emplace_back(argv[i]);
	}

	return config;
}
} // namespace

int main(int argc, char* argv[])
{
	const auto config = parseArguments(argc, argv);
	if (!config.has_value())
	{
		return EXIT_FAILURE;
	}

	LuaApplication app;
	return app.run(*config);
}
