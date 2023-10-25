-- Function to open the default web browser
function openWebBrowser(url)
    os.execute('start "" "' .. url .. '"')
end

-- URL to open
local url = "https://www.youtube.com/watch?v=dQw4w9WgXcQ"

-- Open the web browser
openWebBrowser(url)
