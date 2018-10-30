mb = require("modbus_native")

--bit = require("bit32")
--print ( string.format ( "bit: %s", tostring(bit) ) )

debug_level = 10
mb.type = RTUoTCP
mb.host = "192.168.168.46"
mb.port = 5002
-- print ( string.format ( "mb: %d", mb.type ) )

--mb:readInputStatus(0x01, 0x00, 28 )
frame = mb:readInputRegister(0x01, 0, 10 )

--mb:getFrame()
frame = mb:readHoldingRegister(0x01, 0, 0x06)
--frame = mb:getFrame()
if ( frame == nil or frame.values == nil or frame.exception ~= 0) then
  print ( "Error getting frame" );
  mb:closeDevice()
  return
end

--print ( "Tipo: " .. type ( frame.values ) )
values_string = "Numero valori " .. #frame.values
for key, value in ipairs(frame.values) do
  values_string = values_string .. mb.packetdump ( frame.values[key] )
end
print ( values_string )
mb:closeDevice()

-- minutes = tonumber (string.sub (frame.values[1],1,1), 16 )-- + tonumber(string.sub (frame.values[1],2,2))
--print ( mb.packetdump ( string.sub (frame.values[1],1,2 ) ) )
--minutes = frame.values[1]:byte(1)*256+frame.values[1]:byte(2)
--hours = frame.values[2]:byte(1)*256+frame.values[2]:byte(2)
--week_day = frame.values[3]:byte(1)*256+frame.values[3]:byte(2)
--month_day = frame.values[4]:byte(1)*256+frame.values[4]:byte(2)
--month = frame.values[5]:byte(1)*256+frame.values[5]:byte(2)
--year = frame.values[6]:byte(1)*256+frame.values[6]:byte(2)
----print ( values_string )
--print ( string.format ( "Ore %d:%d del %d/%d/%d (%d)", hours, minutes, month_day, month, year, week_day ) )
-- mb:writeSingleCoil(0x01, 14, 0xff00)
-- mb:getFrame()
-- mb:readInputStatus(0x01, 01, 1 )

--mb:readCoils(0x01, 0x0040, 0x0001)
--mb:print()
--mb:prepareFrame(17, 3, 0x006b, 0x0003 )
--mb:parseFrame ( ":1101056b00037e" )
-- :0105000EFF00ED
--mb:parseFrame ( ":1f0105CD6BB20E1B45E6" )
