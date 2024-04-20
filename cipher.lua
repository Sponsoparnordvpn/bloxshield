function repeat_key(key, length)
    if #key >= length then
        return key:sub(1, length)
    end

    times = math.floor(length / #key)
    remain = length % #key

    result = ''

    for i = 1, times do
        result = result .. key
    end

    if remain > 0 then
        result = result .. key:sub(1, remain)
    end

    return result
end

function xor(message, key)
    rkey = repeat_key(key, #message)

    result = ''

    for i = 1, #message do
        k_char = rkey:sub(i, i)
        m_char = message:sub(i, i)

        k_byte = k_char:byte()
        m_byte = m_char:byte()

        xor_byte = m_byte ~ k_byte

        xor_char = string.char(xor_byte)

        result = result .. xor_char
    end

    return result
end
function generate_key(length)
    local key = ""
    local characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    
    for i = 1, length do
        local random_index = math.random(#characters)
        key = key .. characters:sub(random_index, random_index)
    end
    
    return key
end
local b='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/' -- You will need this for encoding/decoding
function base64encode(data)
     return ((data:gsub('.', function(x) 
        local r,b='',x:byte()
        for i=8,1,-1 do r=r..(b%2^i-b%2^(i-1)>0 and '1' or '0') end
        return r;
    end)..'0000'):gsub('%d%d%d?%d?%d?%d?', function(x)
        if (#x < 6) then return '' end
        local c=0
        for i=1,6 do c=c+(x:sub(i,i)=='1' and 2^(6-i) or 0) end
        return b:sub(c+1,c+1)
    end)..({ '', '==', '=' })[#data%3+1])
end

function base64decode(data)
    data = string.gsub(data, '[^'..b..'=]', '')
    return (data:gsub('.', function(x)
        if (x == '=') then return '' end
        local r,f='',(b:find(x)-1)
        for i=6,1,-1 do r=r..(f%2^i-f%2^(i-1)>0 and '1' or '0') end
        return r;
    end):gsub('%d%d%d?%d?%d?%d?%d?%d?', function(x)
        if (#x ~= 8) then return '' end
        local c=0
        for i=1,8 do c=c+(x:sub(i,i)=='1' and 2^(8-i) or 0) end
            return string.char(c)
    end))
end

function customencode(text,key)
  return base64encode(xor(text,key))
end



local str = [[
{"hwid": "sponsoparnordvpn","key": "test_key","service" : "LandHub"}
]]

print(customencode(str, "6035a8ce0500e111198a0e2770bff702"))

function vigenere_encrypt(plaintext, keyword)
    local encrypted_text = ""
    local keyword_length = #keyword
    local key_index = 1
    
    -- Iterate over each character in the plaintext
    for i = 1, #plaintext do
        local char = plaintext:sub(i, i)
        
        -- Check if the character is an uppercase letter
        if char:match("%u") then
            local char_code = char:byte() - 65  -- Convert character to its corresponding alphabet index (0-25)
            local keyword_char = keyword:sub(key_index, key_index):upper()
            local keyword_code = keyword_char:byte() - 65  -- Convert keyword character to its corresponding alphabet index (0-25)
            local encrypted_char_code = (char_code + keyword_code) % 26  -- Apply Vigenère cipher formula
            local encrypted_char = string.char(encrypted_char_code + 65)  -- Convert back to character
            encrypted_text = encrypted_text .. encrypted_char
            
            -- Update key index for next character
            key_index = (key_index % keyword_length) + 1
        else
            -- If character is not an uppercase letter, leave it unchanged
            encrypted_text = encrypted_text .. char
        end
    end
    
    return encrypted_text
end
-- Function to decrypt ciphertext using Vigenère cipher
function vigenere_decrypt(ciphertext, keyword)
    local decrypted_text = ""
    local keyword_length = #keyword
    local key_index = 1
    
    -- Iterate over each character in the ciphertext
    for i = 1, #ciphertext do
        local char = ciphertext:sub(i, i)
        
        -- Check if the character is an uppercase letter
        if char:match("%u") then
            local char_code = char:byte() - 65  -- Convert character to its corresponding alphabet index (0-25)
            local keyword_char = keyword:sub(key_index, key_index):upper()
            local keyword_code = keyword_char:byte() - 65  -- Convert keyword character to its corresponding alphabet index (0-25)
            local decrypted_char_code = (char_code - keyword_code) % 26  -- Apply Vigenère cipher decryption formula
            local decrypted_char = string.char(decrypted_char_code + 65)  -- Convert back to character
            decrypted_text = decrypted_text .. decrypted_char
            
            -- Update key index for next character
            key_index = (key_index % keyword_length) + 1
        else
            -- If character is not an uppercase letter, leave it unchanged
            decrypted_text = decrypted_text .. char
        end
    end
    
    return decrypted_text
end
print("hello world")