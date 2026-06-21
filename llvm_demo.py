from llvmlite import ir

module = ir.Module(name="demo")

int32 = ir.IntType(32) #type definition



int8p = ir.PointerType(ir.IntType(8)) #definining a pointer to int8

void = ir.VoidType()

fn_add = ir.Function(module, ir.FunctionType(int32, [int32, int32]), name="add") #defining a smple functions to test it


fn_add.args[0].name = "a"
fn_add.args[1].name = "b"

block = fn_add.append_basic_block("entry") #defining a block or body of the function


builder = ir.IRBuilder(block)


result = builder.add(fn_add.args[0], fn_add.args[1], "result")
builder.ret(result)


# FUNCTION 2 — vulnerable unsafe_strcpy
# void unsafe_strcpy(char* dst, char* src)
# missing size parameter — buffer overflow risk
fn_strcpy = ir.Function(module, ir.FunctionType(void, [int8p, int8p]), name="unsafe_strcpy")
fn_strcpy.args[0].name = "dst"
fn_strcpy.args[1].name = "src"
block2 = fn_strcpy.append_basic_block("entry")
ir.IRBuilder(block2).ret_void()


# FUNCTION 3 — vulnerable unsafe_memcpy
# void unsafe_memcpy(char* dst, char* src, int size)
# has a size parameter but no bounds validation
fn_memcpy = ir.Function(module, ir.FunctionType(void, [int8p, int8p, int32]), name="unsafe_memcpy")
fn_memcpy.args[0].name = "dst"
fn_memcpy.args[1].name = "src"
fn_memcpy.args[2].name = "size"
block3 = fn_memcpy.append_basic_block("entry")
ir.IRBuilder(block3).ret_void()


# FUNCTION 4 — safe_read
# void safe_read(char* buf, int len)
# has a length parameter — bounded and safe
fn_safe = ir.Function(module, ir.FunctionType(void, [int8p, int32]), name="safe_read")
fn_safe.args[0].name = "buf"
fn_safe.args[1].name = "len"
block4 = fn_safe.append_basic_block("entry")
ir.IRBuilder(block4).ret_void()

print(module)
