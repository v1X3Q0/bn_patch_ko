struct r_info __packed
{
    enum r_type;
    uint24_t r_sym;
};

enum R_TYPE : uint8_t
{
    R_ARM_CALL = 0x1c,
    R_ARM_JUMP24 = 0x1d,
    R_ARM_V4BX = 0x28,
    R_ARM_PREL31 = 0x2a,
    R_ARM_MOVW_ABS_NC = 0x2b,
    R_ARM_MOVT_ABS = 0x2c
};

struct Elf32_Rel __packed
{
    uint32_t offset;
    struct  __packed
    {
        enum r_type;
        uint24_t r_sym;
    } info;
};
