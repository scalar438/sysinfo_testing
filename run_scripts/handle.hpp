#pragma once
#include <Windows.h>

struct Handle
{
	Handle() { m_handle = NULL; }

	Handle(Handle &&old) noexcept : m_handle(old.m_handle) { old.m_handle = NULL; }

	Handle(HANDLE h) : m_handle(h) {}

	~Handle()
	{
		if (m_handle != NULL) CloseHandle(m_handle);
	}

	Handle &Handle::operator=(Handle &&old) noexcept
	{
		m_handle     = old.m_handle;
		old.m_handle = NULL;
		return *this;
	}

	Handle(const Handle &) = delete;
	Handle &operator=(const Handle &) = delete;

	HANDLE m_handle;
};