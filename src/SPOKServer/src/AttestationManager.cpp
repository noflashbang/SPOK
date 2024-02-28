#include "AttestationManager.h"

AttestationManager* AttestationManager::m_instance = nullptr;

SPOK_Handle AttestationManager::Add(IAttestation attestation)
{
	return Instance()->AddAttestation(attestation);
}

void AttestationManager::Destroy(SPOK_Handle handle)
{
	Instance()->DestroyAttestation(handle);
}

IAttestation AttestationManager::Get(SPOK_Handle handle)
{
	return Instance()->GetAttestation(handle);
}

AttestationManager::AttestationManager()
{
}

AttestationManager::~AttestationManager()
{
}

SPOK_Handle AttestationManager::AddAttestation(IAttestation attestation)
{
	std::lock_guard<std::mutex> lock(m_mutex);
	{
		SPOK_Handle handle = m_handles.size();
		m_handles[handle] = attestation;
		return handle;
	}
}

void AttestationManager::DestroyAttestation(SPOK_Handle handle)
{
	std::lock_guard<std::mutex> lock(m_mutex);
	{
		m_handles.erase(handle);
	}
}

IAttestation AttestationManager::GetAttestation(SPOK_Handle handle)
{
	std::lock_guard<std::mutex> lock(m_mutex);
	{
		return m_handles[handle];
	}
}

