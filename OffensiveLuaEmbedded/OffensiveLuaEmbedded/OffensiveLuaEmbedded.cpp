// OffensiveLuaEmbedded.cpp : This file contains the 'main' function. Program execution begins and ends there.
#include <iostream>

extern "C" {
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
}

//	Linked libraries. 
#pragma comment (lib, "lua51.lib")


int main(int argc, char* argv[])
{
	lua_State* L;
	int error = 0;
	if (argc < 2) {
		printf("No script provided\r\n");
		return EXIT_FAILURE;
	}
	/* Embed LuaJIT and load default libraries*/
	L = luaL_newstate();
	if (L) {
		luaL_openlibs(L);
		luaL_loadfile(L, argv[1]);
		error = lua_pcall(L, 0, 0, 0);
		if (error) {
				fprintf(stderr, "%s", lua_tostring(L, -1));
				lua_pop(L, 1);  /* pop error message from the stack */
		}
		lua_close(L);
	}
	return EXIT_SUCCESS;
}
