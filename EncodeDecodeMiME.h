//--------------------------------------------------------------------------- 
// MIME(QP & Base64) Encode/Decode unit. (H) 
// Copyright (c) 2000, 02 Mental Studio - http://mental.mentsu.com 
// Author : Raptor - raptorz@163.com 
//--------------------------------------------------------------------------- 
#ifndef mimeb64H 
#define mimeb64H 
//--------------------------------------------------------------------------- 
#ifdef __cplusplus 
extern "C" { 
#endif 
int QPEncode( char * const aDest, const unsigned char * aSrc, int aLen ); 
int QPDecode( unsigned char * const aDest, const char * aSrc ); 
int Base64Encode( char * const aDest, const unsigned char * aSrc, int aLen ); 
int Base64Decode( unsigned char * const aDest, const char * aSrc ); 
#ifdef __cplusplus 
} 
#endif 
//--------------------------------------------------------------------------- 


#endif 