#include "stdafx.h"
#include "EncodeDecodeMiME.h"
//--------------------------------------------------------------------------- 
//#pragma package(smart_init) 
//--------------------------------------------------------------------------- 
// 4bit binary to char 0-F 
char Hex2Chr( unsigned char n ) 
{ 
	n &= 0xF; 
	if ( n < 10 ) 
		return ( char )( n + '0' ); 
	else 
		return ( char )( n - 10 + 'A' ); 
} 
//--------------------------------------------------------------------------- 
// char 0-F to 4bit binary 
unsigned char Chr2Hex( char c ) 
{ 
	if ( c >= 'a' && c <= 'z' ) // it's toupper 
		c = c - 'a' + 'A'; 
	if ( c >= '0' && c <= '9' ) 
		return ( int )( c - '0' ); 
	else if ( c >= 'A' && c <= 'F' ) 
		return ( int )( c - 'A' + 10 ); 
	else 
		return -1; 
} 
//--------------------------------------------------------------------------- 
// Base64 code table 
// 0-63 : A-Z(25) a-z(51), 0-9(61), +(62), /(63) 
char Base2Chr( unsigned char n ) 
{ 
	n &= 0x3F; 
	if ( n < 26 ) 
		return ( char )( n + 'A' ); 
	else if ( n < 52 ) 
		return ( char )( n - 26 + 'a' ); 
	else if ( n < 62 ) 
		return ( char )( n - 52 + '0' ); 
	else if ( n == 62 ) 
		return '+'; 
	else 
		return '/'; 
} 
//--------------------------------------------------------------------------- 
unsigned char Chr2Base( char c ) 
{ 
	if ( c >= 'A' && c <= 'Z' ) 
		return ( unsigned char )( c - 'A' ); 
	else if ( c >= 'a' && c <= 'z' ) 
		return ( unsigned char )( c - 'a' + 26 ); 
	else if ( c >= '0' && c <= '9' ) 
		return ( unsigned char )( c - '0' + 52 ); 
	else if ( c == '+' ) 
		return 62; 
	else if ( c == '/' ) 
		return 63; 
	else 
		return 64; // 无效字符 
} 
//--------------------------------------------------------------------------- 
// aLen 为 aSrc 的大小， aDest 所指的缓冲区必须至少为 aLen 的 3 倍！！！ 
// 返回 aDest 的长度 
int QPEncode( char * const aDest, const unsigned char * aSrc, int aLen ) 
{ 
	char * p = aDest; 
	int i = 0; 
	while ( i++ < aLen ) 
	{ 
		*p++ = '='; 
		*p++ = Hex2Chr( *aSrc >> 4 ); 
		*p++ = Hex2Chr( *aSrc++ ); 
	} 
	*p = 0; // aDest is an ASCIIZ string 
	return ( p - aDest ); // exclude the end of zero 
} 
//--------------------------------------------------------------------------- 
// aDest 所指的缓冲区必须至少为 aSrc 长度的 1/3 ！！！ 
// 返回 aDest 的长度 
int QPDecode( unsigned char * const aDest, const char * aSrc ) 
{ 
	unsigned char * p = aDest; 
	int n = strlen( aSrc ); 
	unsigned char ch, cl; 
	while ( *aSrc ) // aSrc is an ASCIIZ string 
	{ 
		if ( ( *aSrc == '=' ) && ( n - 2 > 0 ) ) 
		{ 
			ch = Chr2Hex( aSrc[1] ); 
			cl = Chr2Hex( aSrc[2] ); 
			if ( ( ch == ( unsigned char )-1 ) || ( cl == ( unsigned char )-1 ) ) 
				*p++ = *aSrc++; 
			else 
			{ 
				*p++ = ( ch << 4 ) | cl; 
				aSrc += 3; 
			} 
		} 
		else 
			*p++ = *aSrc++; 
	} 
	return ( p - aDest ); 
} 
//--------------------------------------------------------------------------- 
// aLen 为 aSrc 的长度， aDest 所指的缓冲区必须至少为 aLen 的 1.33 倍！！！ 
// 返回 aDest 的长度 
int Base64Encode( char * const aDest, const unsigned char * aSrc, int aLen ) 
{ 
	char * p = aDest; 
	int i; 
	unsigned char t; 
	for ( i = 0; i < aLen; i++ ) 
	{ 
		switch ( i % 3 ) 
		{ 
		case 0 : 
			*p++ = Base2Chr( *aSrc >> 2 ); 
			t = ( *aSrc++ << 4 ) & 0x3F; 
			break; 
		case 1 : 
			*p++ = Base2Chr( t | ( *aSrc >> 4 ) ); 
			t = ( *aSrc++ << 2 ) & 0x3F; 
			break; 
		case 2 : 
			*p++ = Base2Chr( t | ( *aSrc >> 6 ) ); 
			*p++ = Base2Chr( *aSrc++ ); 
			break; 
		} 
	} 
	if ( aLen % 3 != 0 ) 
	{ 
		*p++ = Base2Chr( t ); 
		if ( aLen % 3 == 1 ) 
			*p++ = '='; 
		*p++ = '='; 
	} 
	*p = 0; // aDest is an ASCIIZ string 
	return ( p - aDest ); // exclude the end of zero 
} 
//--------------------------------------------------------------------------- 
// aDest 所指的缓冲区必须至少为 aSrc 长度的 0.75 倍！！！ 
// 返回 aDest 的长度 
int Base64Decode( unsigned char * const aDest, const char * aSrc ) 
{ 
	unsigned char * p = aDest; 
	int i, n = strlen( aSrc ); 
	unsigned char c, t; 
	for ( i = 0; i < n; i++ ) 
	{ 
		if ( *aSrc == '=' ) 
			break; 
		do { 
			if ( *aSrc ) 
				c = Chr2Base( *aSrc++ ); 
			else 
				c = 65; // 字符串结束 
		} while ( c == 64 ); // 跳过无效字符，如回车等 
		if ( c == 65 ) 
			break; 
		switch ( i % 4 ) 
		{ 
		case 0 : 
			t = c << 2; 
			break; 
		case 1 : 
			*p++ = ( unsigned char )( t | ( c >> 4 ) ); 
			t = ( unsigned char )( c << 4 ); 
			break; 
		case 2 : 
			*p++ = ( unsigned char )( t | ( c >> 2 ) ); 
			t = ( unsigned char )( c << 6 ); 
			break; 
		case 3 : 
			*p++ = ( unsigned char )( t | c ); 
			break; 
		} 
	} 
	return ( p - aDest ); 
} 
//--------