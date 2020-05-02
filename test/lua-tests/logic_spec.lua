ffi.cdef([=[
typedef struct mtev_logic_ast_t mtev_logic_ast_t;
typedef struct mtev_logic_exec_t mtev_logic_exec_t;
typedef bool mtev_boolean;

void free(void *);

typedef enum {
  MTEV_LOGIC_STRING,
  MTEV_LOGIC_INT64,
  MTEV_LOGIC_UINT64,
  MTEV_LOGIC_DOUBLE
} mtev_logic_var_type_t;

typedef struct {
  mtev_logic_var_type_t type;
  struct {
    const char *s;
    int64_t     l;
    double      n;
  } value;
} mtev_logic_var_t;

typedef struct {
  mtev_boolean (*lookup)(void *context, const char *name, mtev_logic_var_t *outvar);
} mtev_logic_ops_t;

mtev_logic_ast_t * mtev_logic_parse(const char *input, char **error);
void mtev_logic_ast_free(mtev_logic_ast_t *);
mtev_logic_exec_t * mtev_logic_exec_alloc(const mtev_logic_ops_t *);
void mtev_logic_exec_free(mtev_logic_exec_t *);
mtev_boolean mtev_logic_exec(mtev_logic_exec_t *, mtev_logic_ast_t *, void *);
void mtev_logic_var_set_string(mtev_logic_var_t *, const char *);
void mtev_logic_var_set_string_copy(mtev_logic_var_t *, const char *);
void mtev_logic_var_set_int64(mtev_logic_var_t *, int64_t);
void mtev_logic_var_set_double(mtev_logic_var_t *, double);
typedef void * mtev_log_stream_t;
void mtev_logic_ast_log(mtev_log_stream_t log, mtev_logic_ast_t *);
mtev_log_stream_t mtev_log_stream_find(const char *);
]=])

local testo = {}
testo['foo'] = "wh'at"
testo['line'] = 120

local 
function lua_context_lookup(ctx, ffiname, var)
  local name = ffi.string(ffiname)
  if testo[name] == nil then return false end
  if type(testo[name]) == "number" then
    if math.floor(testo[name]) == testo[name] then
      libmtev.mtev_logic_var_set_int64(var, testo[name])
    else
      libmtev.mtev_logic_var_set_double(var, testo[name])
    end
  else
    libmtev.mtev_logic_var_set_string_copy(var, testo[name])
  end
  return true
end

function parse(expr)
  local errorout = ffi.new("char*[?]", 1)
  local ast = libmtev.mtev_logic_parse(expr, errorout)
  local err = nil
  if errorout[0] ~= nil then
    err = ffi.string(errorout[0])
  end
  ffi.C.free(errorout[0])
  return ast, err
end

describe("mtev_logic", function()
  local exec
  local lua_ops = ffi.new("mtev_logic_ops_t[?]", 1)
  lua_ops[0].lookup = lua_context_lookup
  it("sets up an operator for execution", function()
    exec = libmtev.mtev_logic_exec_alloc(lua_ops)
  end)

  it("catches errors", function()
    local ast, err = parse("and(foo = 'what', not (a), b)")
    assert.is_not_nil(err)
    assert.is.equal(ast, nil)
  end)

  it("parses", function()
    local ast, err = parse("and(foo = 'wh\\'at' , not(or(message ~ 'te\\\"sting', line < 50)), line > 100)")
    assert.is_nil(err)
    assert.is_not_nil(ast)
    local ls = libmtev.mtev_log_stream_find("error")
    -- don't run this because it prints to stderr
    -- libmtev.mtev_logic_ast_log(ls, ast)
    local t = {}
    assert.is_true(libmtev.mtev_logic_exec(exec, ast, nil))
    libmtev.mtev_logic_ast_free(ast)
  end)

end)
