#ifndef _IR2_H_
#define _IR2_H_

#include "latx-types.h"
#include "la-ir2.h"
#include "error_la.h"


#define IR2_ITEMP_MAX 32

#define itemp_status_num \
    (sizeof(reg_itemp_map) / sizeof(int))
#define ftemp_status_num \
    (sizeof(reg_ftemp_map) / sizeof(int))


void ir2_opnd_build(IR2_OPND *, IR2_OPND_TYPE, int value);
void ir2_opnd_build2(IR2_OPND *, IR2_OPND_TYPE, int base, int16 offset);
void ir2_opnd_build_type(IR2_OPND *, IR2_OPND_TYPE);

IR2_OPND ir2_opnd_new(IR2_OPND_TYPE, int value);
IR2_OPND ir2_opnd_new2(IR2_OPND_TYPE, int base, int16 offset);
IR2_OPND ir2_opnd_new_type(IR2_OPND_TYPE);

static inline IR2_OPND ir2_opnd_new_none(void)
{
    IR2_OPND opnd;

    opnd._type = IR2_OPND_NONE;
    opnd.val = 0;
    opnd._assist = 0;
    return opnd;
}

static inline int32 ir2_opnd_imm(const IR2_OPND *opnd)
{
    return opnd->_imm32;
}

static inline int32 ir2_opnd_offset(const IR2_OPND *opnd)
{
    lsassertm(opnd->_type == IR2_OPND_MEM, "This IR2 must be a MEM type!");
    return opnd->_offset;
}

static inline int ir2_opnd_base_reg_num(const IR2_OPND *opnd)
{
    return opnd->_reg_num;
}

static inline IR2_OPND_TYPE ir2_opnd_type(const IR2_OPND *opnd)
{
    return (IR2_OPND_TYPE)opnd->_type;
}

static inline void ir2_set_opnd_type(IR2_OPND *opnd, const IR2_OPND_TYPE type)
{
    opnd->_type = type;
}

static inline int32 ir2_opnd_label_id(const IR2_OPND *opnd)
{
    return opnd->_label_id;
}

static inline int ir2_opnd_cmp(const IR2_OPND *opnd1, const IR2_OPND *opnd2)
{
    return opnd1->_type == opnd2->_type && opnd1->val == opnd2->val;
}

static inline int ir2_opnd_is_ireg(const IR2_OPND *opnd)
{
    return opnd->_type == IR2_OPND_GPR;
}

static inline int ir2_opnd_is_freg(const IR2_OPND *opnd)
{
    return opnd->_type == IR2_OPND_FPR;
}

static inline int ir2_opnd_is_creg(const IR2_OPND *opnd)
{
    return opnd->_type == IR2_OPND_FCSR;
}

int ir2_opnd_is_itemp(const IR2_OPND *);
int ir2_opnd_is_ftemp(const IR2_OPND *);

static inline int ir2_opnd_is_mem(const IR2_OPND *opnd)
{
    return opnd->_type == IR2_OPND_MEM;
}

static inline int ir2_opnd_is_imm(const IR2_OPND *opnd)
{
    return opnd->_type == IR2_OPND_IMM;
}

static inline int ir2_opnd_is_label(const IR2_OPND *opnd)
{
    return opnd->_type == IR2_OPND_LABEL;
}


int ir2_opnd_to_string(IR2_OPND *, char *, bool);

void ir2_opnd_convert_label_to_imm(IR2_OPND *, int imm);


void ir2_build(IR2_INST *, IR2_OPCODE, IR2_OPND, IR2_OPND, IR2_OPND);

static inline void ir2_set_id(IR2_INST *ir2, int id)
{
    ir2->_id = id;
}

static inline int ir2_get_id(const IR2_INST *ir2)
{
    return ir2->_id;
}

static inline IR2_OPCODE ir2_opcode(const IR2_INST *ir2)
{
    return (IR2_OPCODE)(ir2->_opcode);
}

static inline void ir2_set_opcode(IR2_INST *ir2, IR2_OPCODE type)
{
    ir2->_opcode = type;
}
int ir2_dump(IR2_INST *);
int ir2_to_string(IR2_INST *, char *);
IR2_INST *ir2_prev(const IR2_INST *);
IR2_INST *ir2_next(const IR2_INST *);

void ir2_append(IR2_INST *);
void ir2_remove(IR2_INST *);
void ir2_insert_before(IR2_INST *ir2, IR2_INST *next);
void ir2_insert_after(IR2_INST *ir2, IR2_INST *prev);
IR2_INST *ir2_allocate(void);

uint32 ir2_assemble(IR2_INST *);
bool ir2_op_check(IR2_INST *);

bool ir2_opcode_is_branch(IR2_OPCODE);
bool ir2_opcode_is_branch_with_3opnds(IR2_OPCODE);
bool ir2_opcode_is_branch_with_2opnds(IR2_OPCODE);
bool ir2_opcode_is_f_branch(IR2_OPCODE opcode);
bool ir2_opcode_is_convert(IR2_OPCODE opcode);
bool ir2_opcode_is_fcmp(IR2_OPCODE opcode);

IR2_OPND create_immh_opnd(int val);
IR2_INST *la_append_ir2_opnd0(IR2_OPCODE type);
IR2_INST *la_append_ir2_opndi(IR2_OPCODE type, int imm);
IR2_INST *la_append_ir2_opnd1(IR2_OPCODE type, IR2_OPND op0);
IR2_INST *la_append_ir2_opnd1i(IR2_OPCODE type, IR2_OPND op0, int imm);
IR2_INST *la_append_ir2_opnd2(IR2_OPCODE type, IR2_OPND op0, IR2_OPND op1);
IR2_INST *la_append_ir2_opnd2i(IR2_OPCODE type, IR2_OPND op0,IR2_OPND op1, int imm);
IR2_INST *la_append_ir2_opnd2ii(IR2_OPCODE type, IR2_OPND op0, IR2_OPND op1, int imm0, int imm1);
IR2_INST *la_append_ir2_opnd3(IR2_OPCODE type, IR2_OPND op0,IR2_OPND op1, IR2_OPND op2);
IR2_INST *la_append_ir2_opnd3i(IR2_OPCODE type, IR2_OPND op0, IR2_OPND op1, IR2_OPND op2, int imm0);
IR2_INST *la_append_ir2_opnd4(IR2_OPCODE type, IR2_OPND op0, IR2_OPND op1, IR2_OPND op2, IR2_OPND op3);


IR2_INST *la_append_ir2_opnda(IR2_OPCODE opcode, ADDR addr);
bool la_ir2_opcode_is_store(IR2_OPCODE opcode);
bool la_ir2_opcode_is_load(IR2_OPCODE opcode);

/* from ir2-optimization.c */
void tr_ir2_optimize(void);

void la_append_ir2_jmp_far(ADDR jmp_offset);
#endif
