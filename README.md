# Windows SIEM Query Guard

Run `py investigate.py` from the extracted folder on Windows with Python 3.9 or later and Tkinter. All processing stays local.

1. Choose **Read local Security log** to import the most recent 2,000 successful or failed sign-in events available to your Windows account. Alternatively use **Import XML** with a Windows Event Viewer XML export. The application reads on demand. Import again to refresh.
2. Select an account and the original search parameters. For example choose failed sign-ins in the last 24 hours, followed by **Change outcome to successful**. The window is relative to the instant you confirm the change. An old export may fall entirely outside it.
3. Keep **Exact** for the normal search. Confirm then validate. The screen lists the expected and observed result for each isolated test. A passing query reads the local evidence database in read-only mode and displays up to 200 matching records.
4. Choose **Omit account** or **Ignore case** to exercise a candidate translation error. Confirm and validate again. The account contract matches the exact log label, including the domain and its recorded capitalization. This choice is for log-text filtering, not Windows identity resolution.
5. Compare the returned host and record number with the original Security log. Record types 4624 and 4625 correspond to successful and failed logons, including noninteractive logons. Logon type and IP appear when provided by the source.

## Scope

The local database is stored at `%LOCALAPPDATA%\SIEMQueryGuard\events.sqlite`. It contains imported sign-in metadata. Reimporting overlapping records is supported. Missing audit data, limited read access, the collection cap, retention and time filters affect results. A zero count describes the imported subset. This version supports structured account, outcome and time revisions. It uses local SQLite and does not require an LLM, cloud service or Elasticsearch.

PASS covers the displayed synthetic checks only. FAIL blocks a demonstrated discrepancy or an omitted account. INCONCLUSIVE blocks an unresolved comparison rule. Exact queries use the same SQL, bound values and table definition for isolated validation and read-only evidence retrieval.

Microsoft references:
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625
