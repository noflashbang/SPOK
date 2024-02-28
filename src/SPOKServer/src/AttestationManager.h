#pragma once

#include "SPOKCore.h"
#include "IAttestation.h"
#include "StandardLib.h"

class AttestationManager
{
public:

	static AttestationManager* Instance()
	{
		if (m_instance == nullptr)
		{
			m_instance = new AttestationManager();
		}
		return m_instance;
	}

	static void Destroy()
	{
		if (m_instance != nullptr)
		{
			delete m_instance;
			m_instance = nullptr;
		}
	}

	AttestationManager(const AttestationManager&) = delete;
	AttestationManager& operator=(const AttestationManager&) = delete;

	AttestationManager(AttestationManager&&) = delete;
	AttestationManager& operator=(AttestationManager&&) = delete;

	static SPOK_Handle Add(IAttestation attestation);
	static void Destroy(SPOK_Handle handle);
	static IAttestation Get(SPOK_Handle handle);

protected:
	AttestationManager();
	~AttestationManager();
	

private:

	static AttestationManager* m_instance;

	std::mutex m_mutex;
	std::map<SPOK_Handle, IAttestation> m_handles;

	SPOK_Handle AddAttestation(IAttestation attestation);
	void DestroyAttestation(SPOK_Handle handle);
	IAttestation GetAttestation(SPOK_Handle handle);
};