#pragma

#include "ISPOKAction.h"

class CreateAikAction : public ISPOKAction
{
	public:
		CreateAikAction() = default;
		virtual ~CreateAikAction() = default;

		virtual bool ValidateArguments(const ArgumentParser& parser) override;
		virtual void Execute(const ArgumentParser& parser) override;
		virtual std::wstring UsageLine() const override;
};