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
#define STATUS_INVALID_PARAMETER_2 ((NTSTATUS)0xC00000F0L)

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
#define PhObjectToObjectHeader(Object) \
	((PPH_OBJECT_HEADER)CONTAINING_RECORD((PCHAR)(Object), PH_OBJECT_HEADER, Body))

#ifdef DEBUG
#define ASSUME_ASSERT(Expression) assert(Expression)
#define ASSUME_NO_DEFAULT assert(FALSE)
#else
#define ASSUME_ASSERT(Expression) __assume(Expression)
#define ASSUME_NO_DEFAULT __assume(FALSE)
#endif

#define PH_OBJECT_TYPE_TABLE_SIZE 256

/** The object was allocated from the small free list. */
#define PH_OBJECT_FROM_SMALL_FREE_LIST 0x1
/** The object was allocated from the type free list. */
#define PH_OBJECT_FROM_TYPE_FREE_LIST 0x2

// Object type flags
#define PH_OBJECT_TYPE_USE_FREE_LIST 0x00000001

// Configuration

#define PH_OBJECT_SMALL_OBJECT_SIZE 48
#define PH_OBJECT_SMALL_OBJECT_COUNT 512

// Object type flags
#define PH_OBJECT_TYPE_USE_FREE_LIST 0x00000001
#define PH_OBJECT_TYPE_VALID_FLAGS 0x00000001

/**
 * Gets a pointer to an object from an object header.
 *
 * \param ObjectHeader A pointer to an object header.
 *
 * \return A pointer to an object.
 */
#define PhObjectHeaderToObject(ObjectHeader) ((PVOID) & ((PPH_OBJECT_HEADER)(ObjectHeader))->Body)

/**
 * Calculates the total size to allocate for an object.
 *
 * \param Size The size of the object to allocate.
 *
 * \return The new size, including space for the object header.
 */
#define PhAddObjectHeaderSize(Size) ((Size) + UFIELD_OFFSET(PH_OBJECT_HEADER, Body))

#define HEAP_CLASS_1 0x00001000 // Private heap

#define PhRaiseStatus(Status) RtlRaiseStatus(Status)