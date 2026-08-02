B=http://172.20.0.5:5000
for U in brkA9931 brkB9931; do
  curl -s --max-time 15 -X POST $B/users/v1/register -H "Content-Type: application/json" \
    -d "{\"username\":\"$U\",\"password\":\"Pw1$U\",\"email\":\"$U@t.io\"}" >/dev/null
done
TA=$(curl -s --max-time 15 -X POST $B/users/v1/login -H "Content-Type: application/json" -d '{"username":"brkA9931","password":"Pw1brkA9931"}' | sed -n 's/.*"auth_token": "\([^"]*\)".*/\1/p')
TB=$(curl -s --max-time 15 -X POST $B/users/v1/login -H "Content-Type: application/json" -d '{"username":"brkB9931","password":"Pw1brkB9931"}' | sed -n 's/.*"auth_token": "\([^"]*\)".*/\1/p')
curl -s --max-time 15 -X POST $B/books/v1 -H "Content-Type: application/json" -H "Authorization: Bearer $TA" -d '{"book_title":"bookA9931","secret":"AAA_PRIVATE"}' >/dev/null
curl -s --max-time 15 -X POST $B/books/v1 -H "Content-Type: application/json" -H "Authorization: Bearer $TB" -d '{"book_title":"bookB9931","secret":"BBB_PRIVATE"}' >/dev/null
echo "tokenA=${#TA} tokenB=${#TB}"
