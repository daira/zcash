#include <istream>
#include "crypto/common.h"
#include "script/interpreter.h"

class FastSignatureChecker : public BaseSignatureChecker
{
public:
    virtual bool CheckSig(
        const std::vector<unsigned char>& scriptSig,
        const std::vector<unsigned char>& vchPubKey,
        const CScript& scriptCode,
        uint32_t consensusBranchId) const
    {
        return scriptSig.empty() || (scriptSig[0] & 1);
    }

    virtual bool CheckLockTime(const CScriptNum& nLockTime) const
    {
        return nLockTime.getint() & 1;
    }
};

int fuzz_EvalScript(const uint8_t *data, size_t size) {
    // The container format looks like:
    //
    //   uint8[4] consensusBranchId
    //   uint8[2] flags
    //   uint8[2] nStackEntries
    //   uint8[...][n] stack
    //   uint8[...] script
    //
    // where nStackEntries is a little-endian 2-byte representation of n.

    FastSignatureChecker checker;
    ScriptError serror;

    uint32_t consensusBranchId = ReadLE32(data);
    unsigned int flags         = ReadLE16(data+4);
    size_t n                   = ReadLE16(data+6);
    std::vector<std::vector<unsigned char> > stack;

    CScript script(data+8, data + size);

    return EvalScript(stack, script, flags, checker, consensusBranchId, &serror) ? 1 : 0;
}

#ifdef FUZZ_WITH_AFL

#error "The AFL version of this fuzzer has not yet been implemented."

int main (int argc, char *argv[]) {
    // not implemented
    return 0;
}

#endif // FUZZ_WITH_AFL
#ifdef FUZZ_WITH_LIBFUZZER

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size >= 8) {
        fuzz_EvalScript(Data, Size);
    }
    return 0;
}

#endif
