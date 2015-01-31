-- $Id$
-- Test vectors for PBKDF2-Password

-- Algorithm
INSERT INTO radcheck (username, attribute, op, value) VALUES ('pbkdf2_sha1', 'PBKDF2-Password', ':=', 'HMACSHA1:AAAD6A:Xw1P133xrwk=:dtQBXQRiR/No5A8Ip3JFGF/qUC0=');
INSERT INTO radcheck (username, attribute, op, value) VALUES ('pbkdf2_sha2_224', 'PBKDF2-Password', ':=', 'HMACSHA2+224:AAAnEA:UHScBrg/ZWOyBKqQdAh7bw==:tcFp6CDrkIYdhwa60g24U4ko+mBxzAiFxlpPnA==');
INSERT INTO radcheck (username, attribute, op, value) VALUES ('pbkdf2_sha2_256', 'PBKDF2-Password', ':=', 'HMACSHA2+256:AAAnEA:a/8HbYW2HWsMthN27JI+Ew==:3nPlXYOlOuDCFOfethUomHxTXkG9JCivOdvh6FDNdGw=');
INSERT INTO radcheck (username, attribute, op, value) VALUES ('pbkdf2_sha2_384', 'PBKDF2-Password', ':=', 'HMACSHA2+384:AAAnEA:pyHRsYLfNZdjszRcu6eHrA==:ktGfNmZ6PyD8FNEgPzFK1fypKERZ13pgvFl+PQdyKouaMXsXIiWPuTMXHqDUCWsx');
INSERT INTO radcheck (username, attribute, op, value) VALUES ('pbkdf2_sha2_512', 'PBKDF2-Password', ':=', 'HMACSHA2+512:AAAnEA:TG8Mb94NEmfPLaePwi5CFA==:SYSFeRf9jr4Uo5DB4NvNUEuc1gmEiLjTac5J4WgyKa7mO58KHKWop9xWmcFeuLtUN/iexLTNSgcubOugAyZcog==');
INSERT INTO radcheck (username, attribute, op, value) VALUES ('pbkdf2_sha0', 'PBKDF2-Password', ':=', 'HMACSHA0/:AAAD6A:CPQHPHX5NE8=:ZsVj1s1gDDmSyO4j4UZHDWsx9Ck=');

-- Iteration
INSERT INTO radcheck (username, attribute, op, value) VALUES ('pbkdf2_iter1', 'PBKDF2-Password', ':=', 'HMACSHA2+256:AAAAAQ:OErtptMl2hOxhQqvNw7sNw==:4KkrgL+3Q9j8KlHPivtApBKRZAjyWjtDWmZEz2UjNko=');
INSERT INTO radcheck (username, attribute, op, value) VALUES ('pbkdf2_iter1000', 'PBKDF2-Password', ':=', 'HMACSHA2+256:AAAD6A:yhmqoKrtPLY2KYK6cNjnfw==:Y6gkSZEo4TRtlsryHqnGYZhoe2qn5tJ4IUyyVHb/3WU=');
INSERT INTO radcheck (username, attribute, op, value) VALUES ('pbkdf2_iter1000000', 'PBKDF2-Password', ':=', 'HMACSHA2+256:AA9CQA:fCfnJGMVC1QLtTOPiaSICA==:KCmjMpQ+lokMvyFTl4f4pPJNc0xJq4iHZPdtHa0OEXM=');
INSERT INTO radcheck (username, attribute, op, value) VALUES ('pbkdf2_iter0', 'PBKDF2-Password', ':=', 'HMACSHA2+256:AAAAAP:CuNDJ9NimZoP5ljnPNCBUA==:f09zV7dReGg5SIv/EXY9tCL4XQRr5guhL0Q6UXSKI3c=');

-- Salt
INSERT INTO radcheck (username, attribute, op, value) VALUES ('pbkdf2_salt0', 'PBKDF2-Password', ':=', 'HMACSHA2+256:AAAnEA::4RJEKVFQ5nE8126aURI0cJO9tqy/DIAhq64piBEwshA=');
INSERT INTO radcheck (username, attribute, op, value) VALUES ('pbkdf2_salt1', 'PBKDF2-Password', ':=', 'HMACSHA2+256:AAAnEA:qg==:KQzCdedgOZYFwx+mQp1TKA8VM4fwf02pqSdJEh2ekwM=');
INSERT INTO radcheck (username, attribute, op, value) VALUES ('pbkdf2_salt64', 'PBKDF2-Password', ':=', 'HMACSHA2+256:AAAnEA:msGxE1XuC+wlgRr+H4+ioyxZuiN3KYLUSky2FINDTq7KJylKt4XnqloV+FuHGXUbOu1EWcsFp51u2z8wdXVnQQ==:rAV9BeEJH5kt9uZ6pJt0o5pYpN5LQRe4MAYyk2jvjpU=');
INSERT INTO radcheck (username, attribute, op, value) VALUES ('pbkdf2_salt1024', 'PBKDF2-Password', ':=', 'HMACSHA2+256:AAAnEA:/IUrkJKe+1kzJNBw7aAMbnQuSFZpjbCqPeKso3cbuSUzWinxngxjK8yyZLiWwF+WE/0Gplfx25zZEQNTdRTvjZZNefoxQBR8Hht0FpdU9YiEBaeErwVo63EDEu83+ycvB18uH0IXpJKGSSkIPRfGpHT3BkwJDGo5SqjRJadDsyQzkc/WJCMrrfJ0igaWMxb5eR5J8qfXIjBFepRrOOU6acZGtANW8qvDYLJwN+TMd9Jb1wDDY14eoAlKglTF21S3kewNMkDDyeP+oDYv29t1S/soFUnnB+Pb5IdR6pDy2VDGx4jFZMQGshSHWTYQFqgulavS/tGEF8TvzcorrJZKuksAjKdTSmfZ6j4aBY3U+oMSQ+2lO131pkNfNQuMsDfr72r9wUA2xRgUiL/J7CgKn7mamL2OCaksl0Rw2PGqqIaHvAYS6Q1EoIzsmLNrWBYYqTRLyCGZw6+hUOahYRon2lglGmnuWHPfowU+LgcaR5gF1QjvTXhXQ8I39mB3ePgdi+7TUn644Z1FB+JTqGJbue92x4V40Zyyy+Qdt52QsR49iYokbKAwQRiqfVJ7J8NzCY/kIQnqT9RE0NCxZoMBRzboZxVPchxdpmWGQ9dXP06PqIuDCFFiJlVQUfyPMgOAxIlVJ/9NAmj5MWFdWMrmlBNDx9ihEV1FdTv23iFZH5Ejg+x4D3qN5oOyCDL2i9lobzFXh5z4EDpbbogQaFkUzqKEaxRGPBrfYVOi6XXYujVUnxHJaRxbs2UqjpJNsXMg8f7P78aRvOKCIbW70CHWlt7nF0pA5+kFUQRLXKuq7bW+ivoXKeDW5o4FVP3+Pcr67+DOsUXuehALLj9Mu2ICWlMIV/AWcM2szaqk1bwSo7bAeG4RtDKmNjGA7gpnT+w2x+/qS1eWbc832Sumqc1IA8aY6HNVDPsJZf99To4BR+N0rCoQQ/KIZybI31mQagR3+FR9yNzqWzKIl+qf69RTc1CbUCkKVF8pxWZ0ocP+CAdoKadgpdF8evQIiGcUD73HiJ0RsDWo21y0tN0P5jfzWo3WMhCk9e2wl6o1JAfKw54uHzWJnNlGLBK1LXF+R2m+WvNGBgvUhh4PtYV9gPSudumFdk614oak/Aqcn6xi+YZqOMPkW4WYaiczhHyS7qAyefqKaQkRVYS0Af+79CSjlxZJq57HrD7/1E+d/i0gKmSAbPe80uGHs2a13V3VxztFMBi4xD7zj9Mq7+0goVPD4MNXcR651MZ7vxDRGbvPPmclddZe/nkTEn1YB/909b9mC5P/XzximZYW8gEhBReZouukADRTAjuH8zgSIv6/uyTURnmSVoOumVLBpL7veJIzDm4dZ38BWiasiBnzgMuG9A==:RUoCF5O11OgwLFMTqnKY/yRJy6DYh+yNq4xHZC7COGM=');

-- Base64
INSERT INTO radcheck (username, attribute, op, value) VALUES ('pbkdf2_iter_miss', 'PBKDF2-Password', ':=', 'HMACSHA2+256::E+VXOSsE8RwyYGdygQoW9Q==:UivlvrwHML4VtZHMJLiT/xlH7oyoyvbXQceivptq9TI=');
INSERT INTO radcheck (username, attribute, op, value) VALUES ('pbkdf2_iter_small', 'PBKDF2-Password', ':=', 'HMACSHA2+256:AAAAA:E+VXOSsE8RwyYGdygQoW9Q==:UivlvrwHML4VtZHMJLiT/xlH7oyoyvbXQceivptq9TI=');
INSERT INTO radcheck (username, attribute, op, value) VALUES ('pbkdf2_iter_big', 'PBKDF2-Password', ':=', 'HMACSHA2+256:AAAAAQ==:E+VXOSsE8RwyYGdygQoW9Q==:UivlvrwHML4VtZHMJLiT/xlH7oyoyvbXQceivptq9TI=');
INSERT INTO radcheck (username, attribute, op, value) VALUES ('pbkdf2_salt_small', 'PBKDF2-Password', ':=', 'HMACSHA2+256:AAAAAQ:E+VXOSsE8RwyYGdygQoW9Q=:UivlvrwHML4VtZHMJLiT/xlH7oyoyvbXQceivptq9TI=');
INSERT INTO radcheck (username, attribute, op, value) VALUES ('pbkdf2_salt_big', 'PBKDF2-Password', ':=', 'HMACSHA2+256:AAAAAQ:E+VXOSsE8RwyYGdygQoW9QA==:UivlvrwHML4VtZHMJLiT/xlH7oyoyvbXQceivptq9TI=');
INSERT INTO radcheck (username, attribute, op, value) VALUES ('pbkdf2_dig_small', 'PBKDF2-Password', ':=', 'HMACSHA2+256:AAAAAQ:E+VXOSsE8RwyYGdygQoW9Q==:UivlvrwHML4VtZHMJLiT/xlH7oyoyvbXQceivptq9TI');
INSERT INTO radcheck (username, attribute, op, value) VALUES ('pbkdf2_dig_big', 'PBKDF2-Password', ':=', 'HMACSHA2+256:AAAAAQ:E+VXOSsE8RwyYGdygQoW9Q==:UivlvrwHML4VtZHMJLiT/xlH7oyoyvbXQceivptq9TIA==');
