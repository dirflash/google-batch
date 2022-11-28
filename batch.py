from __future__ import print_function

import os.path

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# If modifying these scopes, delete the file token.json.
SCOPES = ["https://www.googleapis.com/auth/spreadsheets.readonly"]

# The ID and range of a sample spreadsheet.
SAMPLE_SPREADSHEET_ID = "1dhuCKcu2q7U1M_LkMa6E0VqZGSofE_hHzzu79bCXh9k"
# SAMPLE_RANGE_NAME = "Class Data!A2:E"
SAMPLE_RANGE_NAME = "Sheet1!A2:E"


def main():
    """Shows basic usage of the Sheets API.
    Prints values from a sample spreadsheet.
    """
    creds = None
    # The file token.json stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open("token.json", "w") as token:
            token.write(creds.to_json())

    try:
        service = build("sheets", "v4", credentials=creds)

        # Call the Sheets API
        sheet = service.spreadsheets()
        result = (
            sheet.values()
            .get(spreadsheetId=SAMPLE_SPREADSHEET_ID, range=SAMPLE_RANGE_NAME)
            .execute()
        )
        values = result.get("values", [])

        if not values:
            print("No data found.")
            return

        print("Name, Major:")
        for row in values:
            # Print columns A and E, which correspond to indices 0 and 4.
            print("%s, %s" % (row[0], row[4]))
    except HttpError as err:
        print(err)


if __name__ == "__main__":
    main()


"""
    "updateCells": {
        "range": {
            "sheetId": wks_30,
            "startRowIndex": 50,
            "endRowIndex": 55,
            "startColumnIndex": 1,
            "endColumnIndex": 11,
        },
        "rows": [
            {
                "values": [
                    {
                        "advisory_id": "cisco-sa-ise-access-contol-EeufSUCx",
                        "advisory_title": "Cisco Identity Services Engine Insufficient Access Control Vulnerability",
                        "cves": "CVE-2022-20956",
                        "cve_score": "'7.5",
                        "criticality": "High",
                        "psirt_version": "1.4",
                        "first_published": "'2022-11-02T16:00:00",
                        "last_updated": "'2022-11-28T16:06:37",
                        "cve_status": "Interim",
                        "product_names": "['Cisco Identity Services Engine Software ']",
                        "pub_url": "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-access-contol-EeufSUCx",
                    }
                ]
            }
        ],
    }
}

service = build("PSIRT-30", "v4", credentials=sa)

response = (
    service.spreadsheets().batchUpdate(spreadsheetId=wks_30, body=batch_add).execute()
)
"""
