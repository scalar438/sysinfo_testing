#pragma once

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

#define WINDOWS_ANCIENT 0
#define WINDOWS_XP 51
#define WINDOWS_VISTA 60
#define WINDOWS_7 61
#define WINDOWS_8 62
#define WINDOWS_8_1 63
#define WINDOWS_10 100 // TH1
#define WINDOWS_10_TH2 101
#define WINDOWS_10_RS1 102
#define WINDOWS_10_RS2 103
#define WINDOWS_10_RS3 104
#define WINDOWS_10_RS4 105
#define WINDOWS_10_RS5 106
#define WINDOWS_10_19H1 107
#define WINDOWS_10_19H2 108
#define WINDOWS_NEW ULONG_MAX

#define WOW64_POINTER(Type) ULONG
#define RTL_MAX_DRIVE_LETTERS 32

//
// MessageId: STATUS_INVALID_PARAMETER_2
//
// MessageText:
//
// An invalid parameter was passed to a service or function as the second argument.
//
#define STATUS_INVALID_PARAMETER_2       ((NTSTATUS)0xC00000F0L)

#define GDI_HANDLE_BUFFER_SIZE32 34
#define GDI_HANDLE_BUFFER_SIZE64 60

#ifndef _WIN64
#define GDI_HANDLE_BUFFER_SIZE GDI_HANDLE_BUFFER_SIZE32
#else
#define GDI_HANDLE_BUFFER_SIZE GDI_HANDLE_BUFFER_SIZE64
#endif

#define PTR_ADD_OFFSET(Pointer, Offset) ((PVOID)((ULONG_PTR)(Pointer) + (ULONG_PTR)(Offset)))

/**
 * Gets a pointer to the object header for an object.
 *
 * \param Object A pointer to an object.
 *
 * \return A pointer to the object header of the object.
 */
#define PhObjectToObjectHeader(Object) ((PPH_OBJECT_HEADER)CONTAINING_RECORD((PCHAR)(Object), PH_OBJECT_HEADER, Body))

#ifdef DEBUG
#define ASSUME_ASSERT(Expression) assert(Expression)
#define ASSUME_NO_DEFAULT assert(FALSE)
#else
#define ASSUME_ASSERT(Expression) __assume(Expression)
#define ASSUME_NO_DEFAULT __assume(FALSE)
#endif