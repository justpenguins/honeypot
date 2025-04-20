# Set the base URL of your honeypot
$baseUrl = "http://localhost:80"

# Simulate fake login attempts
$body = @{
    username = "admin' OR 1=1 --"
    password = "password123"
}
Invoke-WebRequest -Uri "$baseUrl/login" -Method POST -Body $body | Out-Null

# Simulate command injection
$body = @{
    username = "test"
    password = "pass; rm -rf /"
}
Invoke-WebRequest -Uri "$baseUrl/login" -Method POST -Body $body | Out-Null

# Simulate JSON-based API call (e.g., potential SSRF or XSS)
$json = @{
    username = "<script>alert('xss')</script>"
    password = "password"
} | ConvertTo-Json

Invoke-WebRequest -Uri "$baseUrl/login" -Method POST -Body $json -ContentType "application/json" | Out-Null

Write-Host "Simulated attacks."
