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

print(module)