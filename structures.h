#pragma once
#include <string>

using namespace std;

struct PRODUCT
{
	wstring name;
	wstring id;
	wstring version;
	wstring publisher;
};

struct PROCESS
{
	wstring caption;
	wstring id;
	wstring path;
	wstring handles;
};

struct SERVICE
{
	wstring name;
	wstring id;
	wstring start;
	wstring state;
	wstring status;
};

struct LOGICALDISK
{
	wstring id;
	wstring type;
	wstring freespace;
	wstring size;
};

struct PROCESSOR
{
	wstring caption;
	wstring id;
	wstring manufacturer;
	wstring speed;
	wstring name;
	wstring socket;
};

struct BIOS
{
	wstring biosversion;
	wstring manufacturer;
	wstring name;
	wstring number;
	wstring version;
};

struct HARDDRIVE
{
	wstring parts;
	wstring id;
	wstring model;
	wstring size;
	wstring caption;
};

struct OS
{
	wstring dir;
	wstring id;
	wstring caption;
	wstring number;
	wstring version;
};

struct ANTIPRODUCT
{
	wstring name;
	wstring guid;
	wstring exepath;
	wstring time;
};

struct FIREWALL
{
	wstring guid;
	wstring exepath;
	wstring time;
};