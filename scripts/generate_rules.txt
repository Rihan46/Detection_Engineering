import feedparser
from openai import OpenAI
import json
import os
import sys
import calendar
from datetime import datetime, timedelta, timezone
import time
from jinja2 import Environment, FileSystemLoader
from difflib import SequenceMatcher
import google.generativeai as genai
import math

# Set UTF-8 encoding for stdout to handle emojis/non-ascii chars on Windows
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

# --- Configuration ---
DEEPSEEK_API_KEY = os.environ.get("DEEPSEEK_API_KEY", "")
DEEPSEEK_API_BASE = "https://api.deepseek.com"
DEEPSEEK_MODEL = "deepseek-chat" # "deepseek-chat" corresponds to DeepSeek-V3/V4, "deepseek-reasoner" corresponds to DeepSeek-R1

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
EMBEDDING_MODEL = "models/gemini-embedding-2"
SIMILARITY_THRESHOLD = 0.95

RSS_FEEDS = [
    {"name": "Unit 42", "url": "https://unit42.paloaltonetworks.com/feed/"},
    {"name": "The DFIR Report", "url": "https://thedfirreport.com/feed/"},
    {"name": "Red Canary", "url": "https://redcanary.com/blog/feed/"},
    {"name": "Mandiant", "url": "https://www.mandiant.com/resources/blog/rss.xml"},
    {"name": "DFIR Radar", "url": "https://falhumaid.github.io/DFIR_Radar_RSS/rss.xml"},
    {"name": "CISA Alerts", "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml"}
]
OUTPUT_HTML = "report.html"
OUTPUT_CSV = "rules.csv"
HISTORY_FILE = "processed_rules.json"

client = None

def load_history():
    """Loads processed rules and article URLs from the history file."""
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading history file: {e}")
    return {"processed_articles": [], "historical_rules": []}

def save_history(history):
    """Saves processed rules and article URLs to the history file."""
    try:
        with open(HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(history, f, indent=4, ensure_ascii=False)
    except Exception as e:
        print(f"Error saving history file: {e}")

def cosine_similarity(v1, v2):
    """Computes the cosine similarity between two vectors."""
    if not v1 or not v2:
        return 0.0
    dot_product = sum(x * y for x, y in zip(v1, v2))
    mag1 = math.sqrt(sum(x * x for x in v1))
    mag2 = math.sqrt(sum(x * x for x in v2))
    if not mag1 or not mag2:
        return 0.0
    return dot_product / (mag1 * mag2)

def get_embeddings_batch(texts):
    """Retrieves embedding vectors for a list of texts in a single batch API call."""
    if not texts:
        return []
    try:
        response = genai.embed_content(
            model=EMBEDDING_MODEL,
            content=texts
        )
        return response['embedding']
    except Exception as e:
        print(f"Error fetching embeddings batch: {e}")
        return [None] * len(texts)

def get_embedding(text):
    """Retrieves the embedding vector for a single text."""
    embeddings = get_embeddings_batch([text])
    return embeddings[0] if embeddings else None

def get_rule_text_representation(rule):
    """Returns the text representation of a rule to be used for generating embeddings."""
    name = rule.get("rule_name", "").strip()
    condition = rule.get("condition", "").strip()
    return f"Rule Name: {name}\nKQL: {condition}"

def is_ip_only_rule(condition):
    """Checks if a rule condition only detects based on IP addresses."""
    import re
    cond_lower = condition.lower()
    
    # Extract all field names in the query.
    # In KQL, a field name is followed by a colon (with optional whitespace)
    # e.g. "destination.ip :", "process.name:"
    fields = re.findall(r'\b([\w\.\-]+)\s*:', cond_lower)
    
    if not fields:
        # Fallback check if fields are not matched but IP references are present
        has_ip = any(term in cond_lower for term in ["destination.ip", "source.ip", "client.ip", "server.ip", "host.ip", "ipaddress", "ip_address"])
        if not has_ip:
            return False
        other_keywords = [
            "process", "event", "file", "registry", "port", "user", 
            "protocol", "url", "http", "dns", "winlog", "system", "host.name"
        ]
        has_other = any(kw in cond_lower for kw in other_keywords)
        return not has_other

    # Check if we have at least one IP field and check if there are non-IP fields.
    has_ip_field = False
    has_non_ip_field = False
    
    for field in fields:
        is_ip = (
            field == "ip" or 
            field.endswith(".ip") or 
            field.endswith("_ip") or 
            "ipaddress" in field or 
            "ip_address" in field
        )
        if is_ip:
            has_ip_field = True
        else:
            has_non_ip_field = True
            
    # If the query specifies IP fields but NO non-IP fields, it is an IP-only rule.
    if has_ip_field and not has_non_ip_field:
        return True
        
    return False

def configure_deepseek():
    """Configures the DeepSeek API client."""
    global client
    client = OpenAI(
        api_key=DEEPSEEK_API_KEY,
        base_url=DEEPSEEK_API_BASE
    )
    
def fetch_threat_intel(feeds, max_entries_per_feed=10):
    """Fetches entries from multiple RSS feeds, filtering for those within the last 7 days."""
    all_entries = []
    now = datetime.now(timezone.utc)
    seven_days_ago = now - timedelta(days=7)
    
    for feed_info in feeds:
        print(f"Fetching RSS feed from: {feed_info['name']} ({feed_info['url']})")
        feed = feedparser.parse(feed_info['url'])
        feed_count = 0
        
        for entry in feed.entries:
            # feedparser provides a struct_time in published_parsed
            if hasattr(entry, "published_parsed") and entry.published_parsed:
                published_dt = datetime.fromtimestamp(calendar.timegm(entry.published_parsed), tz=timezone.utc)
                if published_dt < seven_days_ago:
                    continue
            else:
                continue

            all_entries.append({
                "title": entry.title,
                "link": entry.link,
                "summary": entry.summary,
                "published": entry.get("published", "Unknown Date"),
                "source_name": feed_info['name']
            })
            feed_count += 1
            if feed_count >= max_entries_per_feed:
                break
                
        print(f"  Found {feed_count} recent articles from {feed_info['name']}.")
        
    return all_entries

def generate_siem_rules(article, existing_rules=None):
    """Uses DeepSeek to generate Elastic Common Schema (ECS) detection rules from threat intel."""
    print(f"Analyzing article: [{article['source_name']}] {article['title']}...")
    
    global client
    if not client:
        print("DeepSeek client is not configured!")
        return []
        
    # Format the existing rules for the prompt context to prevent duplication
    existing_rules_context = ""
    if existing_rules:
        existing_rules_context = "Here is the list of active detection rules already in our repository:\n"
        for i, r in enumerate(existing_rules, 1):
            existing_rules_context += f"{i}. Rule Name: \"{r.get('rule_name')}\" | KQL: `{r.get('condition')}` | Technique: {r.get('mitre_technique', 'N/A')} | Process: {r.get('target_process', 'N/A')}\n"
        existing_rules_context += "\nCRITICAL: Do NOT generate any rules that detect the same behaviors, processes, or techniques as the existing rules listed above. Only extract unique detection logic for gaps not covered by these rules."
    else:
        existing_rules_context = "No existing rules in the repository."
    
    prompt = f"""
    You are an expert Threat Detection Engineer. Your task is to analyze the following threat intelligence report summary and extract detection rules for a SIEM environment using Elastic Common Schema (ECS) fields.

    Source: {article['source_name']}
    Title: {article['title']}
    Summary: {article['summary']}
    
    {existing_rules_context}
    
    Based on the threat behaviors, IOCs (Indicators of Compromise), or tactics described in the summary, formulate one or more detection rules. If the report covers multiple distinct techniques or indicators, create a separate rule for each.

    CRITICAL EXCLUSIONS:
    - Do NOT generate any rules related to UEBA (User and Entity Behavior Analytics) anomalies.
    - Do NOT generate any rules related to native cloud environments or cloud audit logs (such as AWS CloudTrail, Google Cloud Audit Logs, GCP stackdriver, Azure Activity Logs, Azure AD, SharePoint/Exchange cloud audits, iManage logs).
    - Do NOT generate any rules related to macOS, iOS, or Android operating systems. Focus strictly on Windows and Linux host-based log sources.
    - Do NOT generate any rules that detect solely on static IP addresses or lists of IP addresses. If a rule uses an IP address, it must be combined with at least one other parameter (such as process.name, destination.port, registry.path, event.code, etc.). Rules checking only destination.ip or source.ip alone are strictly prohibited.
    - Focus strictly on endpoint-centric log sources (such as process execution, command-line arguments, local file changes, registry modifications, local DNS queries, and host-based network connections).

    All detection rules MUST be formatted using Elastic Common Schema (ECS) fields in Kibana Query Language (KQL) format.
    
    ECS / KQL Guidelines:
    - Map events to standard ECS fields:
      - `event.code` (use for Windows/Linux Event IDs, e.g., "4688", "1", "11", "5136")
      - `process.executable` or `process.name`
      - `process.command_line`
      - `process.parent.executable` or `process.parent.name`
      - `file.path` or `file.name`
      - `registry.path` or `registry.value`
      - `destination.ip` or `destination.port`
      - `dns.question.name`
      - `url.path` or `url.query`
    - Use Kibana Query Language (KQL) operators: `:` (match), `and`, `or`, `not`, wildcard `*`, and parentheses `()` for grouping.
    - Example 1: `event.code : "4688" and process.name : "powershell.exe" and process.command_line : *encodedCommand*`
    - Example 2: `event.code : "1" and process.name : "cmd.exe" and process.command_line : *mshta*`

    You MUST output your response strictly as a JSON object containing a "rules" key which holds an array of rule objects.
    Each object in the array must have the following keys:
    - "rule_name": A concise, descriptive name for the rule.
    - "description": A brief explanation of what the rule detects and why it's important.
    - "event_id": The primary Event ID (e.g. "4688", "1", "11", "5136") if applicable. If the rule is generic (network/endpoint-based) and does not map to a standard Event ID, use "N/A".
    - "mitre_technique": The MITRE ATT&CK technique ID associated with the detection (e.g., "T1048", "T1567", "T1059.001"). If it does not map to a specific technique, use "N/A".
    - "target_process": The primary process name, binary executable, or service being monitored (e.g., "rclone.exe", "winscp.exe", "powershell.exe"). If the rule targets network connections, registry paths, or is generic, use "N/A".
    - "severity": The severity level of the detection rule based on the threat impact (choose exactly one of: "Critical", "High", "Medium", "Low").
    - "condition": The actual KQL query string in ECS format. Do not include markdown code block formatting inside the JSON value. Double quotes inside strings must be escaped.

    Example Output format:
    {{
        "rules": [
            {{
                "rule_name": "Elastic ECS - Suspicious PowerShell Execution",
                "description": "Detects suspicious PowerShell execution with encoded command using Windows Security Log in ECS.",
                "event_id": "4688",
                "mitre_technique": "T1059.001",
                "target_process": "powershell.exe",
                "severity": "High",
                "condition": "event.code : \\"4688\\" and process.name : \\"powershell.exe\\" and process.command_line : *encodedCommand*"
            }}
        ]
    }}
    """
    
    try:
        response = client.chat.completions.create(
            model=DEEPSEEK_MODEL,
            messages=[
                {"role": "user", "content": prompt}
            ],
            response_format={"type": "json_object"},
            stream=False
        )
        response_text = response.choices[0].message.content.strip()
        
        data = json.loads(response_text)
        rules_data = data.get("rules", [])
        
        if isinstance(rules_data, dict):
            rules_data = [rules_data]
            
        for rule in rules_data:
            rule["source_url"] = article["link"]
            rule["source_name"] = article["source_name"]
            rule["published"] = article["published"]
            rule["rule_type"] = "SIEM"
            rule["logic_type"] = "Elastic ECS"
            
        return rules_data
    except Exception as e:
        print(f"Error generating rules for '{article['title']}': {e}")
        return []

def generate_html_report(rules, output_file):
    """Generates an HTML report using Jinja2."""
    print(f"Generating HTML report: {output_file}")
    
    # Get the directory of the current script to locate templates
    script_dir = os.path.dirname(os.path.abspath(__file__))
    templates_dir = os.path.join(script_dir, "templates")
    
    env = Environment(loader=FileSystemLoader(templates_dir))
    template = env.get_template("report_template.html")
    
    unique_sources = sorted(list(set(rule['source_name'] for rule in rules)))
    
    # Calculate counts per provider
    source_counts = {}
    for rule in rules:
        src = rule['source_name']
        source_counts[src] = source_counts.get(src, 0) + 1
        
    # Calculate counts per severity
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for rule in rules:
        sev = rule.get("severity", "Medium")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
    html_out = template.render(
        rules=rules, 
        unique_sources=unique_sources,
        source_counts=source_counts,
        severity_counts=severity_counts
    )
    
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_out)
        
    print(f"Successfully created {output_file}")

def generate_csv_report(rules, output_file):
    """Generates a CSV report containing source, rule name, description, and KQL logic."""
    print(f"Generating CSV report: {output_file}")
    import csv
    try:
        with open(output_file, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f)
            writer.writerow(["Source", "Rule Name", "Description", "Logic"])
            for rule in rules:
                writer.writerow([
                    rule.get("source_name", ""),
                    rule.get("rule_name", ""),
                    rule.get("description", ""),
                    rule.get("condition", "")
                ])
        print(f"Successfully created {output_file}")
    except Exception as e:
        print(f"Error generating CSV report: {e}")

def main():
    # Validate that required environment variables are set
    if not DEEPSEEK_API_KEY:
        print("Error: DEEPSEEK_API_KEY environment variable is not set.")
        print("Please set it in your environment before running:")
        print("  Windows (PowerShell): $env:DEEPSEEK_API_KEY=\"your_key\"")
        print("  Linux/macOS (Bash):  export DEEPSEEK_API_KEY=\"your_key\"")
        sys.exit(1)

    if not GEMINI_API_KEY:
        print("Error: GEMINI_API_KEY environment variable is not set.")
        print("Please set it in your environment before running:")
        print("  Windows (PowerShell): $env:GEMINI_API_KEY=\"your_key\"")
        print("  Linux/macOS (Bash):  export GEMINI_API_KEY=\"your_key\"")
        sys.exit(1)

    # Configure API clients
    genai.configure(api_key=GEMINI_API_KEY)
    configure_deepseek()
    
    # Load history for deduplication
    history = load_history()
    processed_articles = history.get("processed_articles", [])
    processed_titles = history.get("processed_titles", [])
    historical_rules = history.get("historical_rules", [])
    
    processed_urls_set = set(processed_articles)
    processed_titles_set = {t.strip().lower() for t in processed_titles}

    # One-time automatic backfill for existing historical rules missing embeddings
    rules_missing_embeddings = [r for r in historical_rules if "embedding" not in r]
    if rules_missing_embeddings:
        print(f"Found {len(rules_missing_embeddings)} historical rules missing embeddings. Backfilling now...")
        texts_to_embed = [get_rule_text_representation(r) for r in rules_missing_embeddings]
        
        # Batch in chunks of 50 to avoid API batch size limits
        chunk_size = 50
        embeddings = []
        for i in range(0, len(texts_to_embed), chunk_size):
            chunk = texts_to_embed[i:i + chunk_size]
            embeddings.extend(get_embeddings_batch(chunk))
            
        for rule, embedding in zip(rules_missing_embeddings, embeddings):
            if embedding:
                rule["embedding"] = embedding
        
        # Save back to history file immediately
        history["historical_rules"] = historical_rules
        save_history(history)
        print("Backfill complete and saved.")

    # 1. Fetch data
    articles = fetch_threat_intel(RSS_FEEDS)
    if not articles:
        print("No articles found in the RSS feeds from the last 7 days.")
        return
        
    # Deduplicate articles at fetch level (both by link and title to handle dynamic URL trackers)
    new_articles = []
    for article in articles:
        link = article["link"]
        title_lower = article["title"].strip().lower()
        if link in processed_urls_set or title_lower in processed_titles_set:
            print(f"Skipping already processed article: {article['title']} ({article['link']})")
            continue
        new_articles.append(article)
        
    if not new_articles:
        print("No new articles to process after deduplication. Displaying accumulated historical rules.")
        sorted_rules = sorted(historical_rules, key=lambda r: r.get("added_at", ""), reverse=True)
        generate_html_report(sorted_rules, OUTPUT_HTML)
        generate_csv_report(sorted_rules, OUTPUT_CSV)
        return
        
    # 2. Process with AI
    new_rules = []
    for article in new_articles:
        # Pass the full accumulated list of rules so far as context for the prompt
        all_prior_rules = historical_rules + new_rules
        rules = generate_siem_rules(article, all_prior_rules)
        if rules:
            for rule in rules:
                cond_str = rule.get("condition", "")
                if is_ip_only_rule(cond_str):
                    print(f"Skipping rule '{rule.get('rule_name')}' as it is an IP-only rule.")
                    continue
                
                cond = cond_str.strip().lower()
                name = rule.get("rule_name", "").strip().lower()
                tech = rule.get("mitre_technique", "N/A").strip().upper()
                proc = rule.get("target_process", "N/A").strip().lower()
                
                # Generate embedding for the new rule
                rule_text = get_rule_text_representation(rule)
                rule_emb = get_embedding(rule_text)
                if rule_emb:
                    rule["embedding"] = rule_emb
                
                # Check for duplicate/similar rules (as a safety net)
                is_duplicate = False
                for prior_rule in all_prior_rules:
                    prior_cond = prior_rule.get("condition", "").strip().lower()
                    prior_name = prior_rule.get("rule_name", "").strip().lower()
                    prior_tech = prior_rule.get("mitre_technique", "N/A").strip().upper()
                    prior_proc = prior_rule.get("target_process", "N/A").strip().lower()
                    prior_emb = prior_rule.get("embedding")
                    
                    # 1. Compare using embeddings if available (globally without process/technique restrictions)
                    if rule_emb and prior_emb:
                        similarity = cosine_similarity(rule_emb, prior_emb)
                        if similarity >= SIMILARITY_THRESHOLD:
                            is_duplicate = True
                            print(f"Skipping duplicate or highly similar rule (similarity: {similarity:.4f}): {rule.get('rule_name')}")
                            break
                    else:
                        # 2. Fallback to SequenceMatcher (requires metadata overlap to avoid false character matches)
                        tech_overlap = (tech == "N/A" or prior_tech == "N/A" or tech == prior_tech)
                        proc_overlap = (proc == "N/A" or prior_proc == "N/A" or proc == prior_proc)
                        
                        if not (tech_overlap and proc_overlap):
                            continue
                            
                        cond_ratio = SequenceMatcher(None, cond, prior_cond).ratio()
                        name_ratio = SequenceMatcher(None, name, prior_name).ratio()
                        
                        if cond_ratio >= 0.80 or name_ratio >= 0.80:
                            is_duplicate = True
                            print(f"Skipping duplicate or highly similar rule (SequenceMatcher): {rule.get('rule_name')}")
                            break
                        
                if is_duplicate:
                    continue
                
                new_rules.append(rule)
                all_prior_rules.append(rule) # Update in-memory copy for the current loop
                
            # Mark article as processed once rules are successfully fetched/processed
            processed_articles.append(article["link"])
            processed_titles.append(article["title"])

    # 3. Update history database
    for rule in new_rules:
        # Save a clean copy of the rule to history metadata
        historical_rules.append({
            "rule_name": rule.get("rule_name"),
            "description": rule.get("description"),
            "rule_type": rule.get("rule_type"),
            "logic_type": rule.get("logic_type"),
            "event_id": rule.get("event_id"),
            "mitre_technique": rule.get("mitre_technique", "N/A"),
            "target_process": rule.get("target_process", "N/A"),
            "severity": rule.get("severity", "Medium"),
            "condition": rule.get("condition"),
            "source_name": rule.get("source_name"),
            "source_url": rule.get("source_url"),
            "published": rule.get("published"),
            "embedding": rule.get("embedding"),
            "added_at": datetime.now().isoformat()
        })
        
    history["processed_articles"] = processed_articles
    history["processed_titles"] = processed_titles
    history["historical_rules"] = historical_rules
    save_history(history)
            
    # 4. Output HTML containing the full cumulative database of unique rules (newest first)
    sorted_rules = sorted(historical_rules, key=lambda r: r.get("added_at", ""), reverse=True)
    generate_html_report(sorted_rules, OUTPUT_HTML)
    generate_csv_report(sorted_rules, OUTPUT_CSV)

if __name__ == "__main__":
    main()
