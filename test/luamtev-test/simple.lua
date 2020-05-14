module(..., package.seeall)

function main()
  print("main")
  os.exit(0)
end

function alternate()
  print("alternate")
  os.exit(0)
end

function interactive()
  print("interactive")
end
