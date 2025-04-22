import json
import re
import time
import os

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

# Read the Zendesk export JSON file
with open("zd-export.json", "r", encoding="utf-8") as f:
    data = json.load(f)

# Build a list of tuples (ticket_id, formatted_comments_url)
formatted_urls = []
# Assuming the tickets are stored under the "results" key
for ticket in data.get("results", []):
    ticket_url = ticket.get("url", "")
    # Use regex to capture the ticket ID from the URL
    match = re.search(r"/tickets/(\d+)\.json", ticket_url)
    if match:
        ticket_id = match.group(1)
        # Format the URL to access the comments endpoint for the ticket
        comment_url = f"https://wpengine.zendesk.com/api/v2/tickets/{ticket_id}/comments"
        formatted_urls.append((ticket_id, comment_url))

print("Formatted Comment URLs:")
for tid, url in formatted_urls:
    print(f"{tid}: {url}")

# Launch Chrome using Selenium
driver = webdriver.Chrome()  # Ensure chromedriver is in your PATH or specify its location
# Open the Zendesk agent dashboard that requires manual login via OKTA MFA
driver.get("https://wpengine.zendesk.com/agent/dashboard")

# Wait until the dashboard has loaded by checking the URL
WebDriverWait(driver, 300).until(EC.url_contains("agent/dashboard"))
# Alternatively, after reaching the dashboard, you can prompt the user to confirm login completion:
input("Please complete the login (including OKTA multifactor) and then press Enter to continue...")

# Iterate over the formatted URLs, load each, and save the JSON response to a file
for ticket_id, url in formatted_urls:
    driver.get(url)
    # Wait for the JSON response to be loaded.
    # Often the JSON is rendered inside a <pre> tag.
    try:
        pre_element = WebDriverWait(driver, 30).until(
            EC.presence_of_element_located((By.TAG_NAME, "pre"))
        )
        json_text = pre_element.text
    except Exception as e:
        print(f"Error retrieving data for ticket {ticket_id}: {e}")
        continue

    filename = f"{ticket_id}_comments.json"
    with open(filename, "w", encoding="utf-8") as outfile:
        outfile.write(json_text)
    print(f"Saved comments for ticket {ticket_id} to {filename}")
    # Pause briefly between requests
    time.sleep(2)

driver.quit()