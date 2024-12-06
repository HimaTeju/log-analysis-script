import pandas as pd

def parse_log_file(log_file_path):
    """
    Parses the log file and returns a pandas DataFrame with structured log data.
    The columns will be: IP, Time, Method, Endpoint, Status, Size, Message.
    
    :param log_file_path: Path to the log file to be parsed.
    :return: DataFrame with structured log data containing columns ['IP', 'Time', 'Method', 'Endpoint', 'Status', 'Size', 'Message'].
    """
    
    data = []
    
    # Read the file line by line
    with open(log_file_path, "r") as file:
        for line in file:
            parts = line.strip().split(" ")

            # Extract fixed parts
            ip = parts[0]
            time = parts[3].strip("[]") + " " + parts[4].strip("[]")
            method = parts[5].strip('"')
            endpoint = parts[6]          # Endpoint (e.g., /home)
            status = parts[8]
            size = parts[9]

            # Check if there is a message
            message = " ".join(parts[10:]) if len(parts) > 10 else ""

 
            data.append([ip, time, method, endpoint, status, size, message])

    df = pd.DataFrame(data, columns=["IP", "Time", "Method", "Endpoint", "Status", "Size", "Message"])
    
    return df


def count_requests_by_ip(df):
    """
    Counts the number of requests made by each IP address and returns a DataFrame with the request count.
    The output DataFrame is sorted in descending order by request count.
    
    :param df: The DataFrame containing parsed log data with a column 'IP'.
    :return: DataFrame with columns ['IP Address', 'Request Count'], sorted by 'Request Count' in descending order.
    """
    ip_counts = df["IP"].value_counts()  # Count the occurrences of each IP address

    # Create a new DataFrame for better formatting and sort by Request Count
    ip_counts_df = ip_counts.reset_index()
    ip_counts_df.columns = ['IP Address', 'Request Count']
    ip_counts_df = ip_counts_df.sort_values(by='Request Count', ascending=False).reset_index(drop=True)

    return ip_counts_df


def most_frequent_endpoint(df):
    """
    Identifies the most frequently accessed endpoint and returns the endpoint with its access count.
    
    :param df: The DataFrame containing parsed log data with a column 'Endpoint'.
    :return: A string with the most frequently accessed endpoint and the number of times it was accessed.
    """
    endpoint_counts = df["Endpoint"].value_counts()  # Count the occurrences of each endpoint

    # Get the most frequently accessed endpoint and its count
    most_frequent = endpoint_counts.idxmax()
    count = endpoint_counts.max()

    
    return f"Most Frequently Accessed Endpoint:\n{most_frequent} (Accessed {count} times)"


def detect_suspicious_activity(df, threshold=10):
    """
    Detects suspicious activity related to failed login attempts by identifying IP addresses
    with failed login attempts exceeding a specified threshold. This is determined by looking
    for HTTP status code 401 or messages containing "Invalid credentials".
    
    :param df: The DataFrame containing parsed log data with columns 'Status' and 'Message'.
    :param threshold: The number of failed login attempts a user must exceed to be flagged as suspicious (default is 10).
    :return: A DataFrame with columns ['IP Address', 'Failed Login Attempts'] for flagged IP addresses, or None if no suspicious activity is detected.
    """
    # Filter rows where the status is 401 or the message indicates a failed login
    failed_logins = df[(df['Status'] == 401) | (df['Message'].str.contains("Invalid credentials", na=False))]

    # Count the number of failed login attempts per IP address
    failed_login_counts = failed_logins['IP'].value_counts()

    # Filter IPs where the number of failed login attempts exceeds the threshold
    suspicious_ips = failed_login_counts[failed_login_counts > threshold]

    
    if not suspicious_ips.empty:
        suspicious_df = pd.DataFrame({
            'IP Address': suspicious_ips.index,
            'Failed Login Attempts': suspicious_ips.values
        })
        return suspicious_df
    else:
        return None

def save_results_to_csv(ip_counts_sorted, most_frequent, suspicious_ips):
    """
    Save the analysis results to a CSV file with three sections: 
    1. Requests per IP
    2. Most Accessed Endpoint
    3. Suspicious Activity
    
    :param ip_counts_sorted: DataFrame containing the IP addresses and request counts
    :param most_frequent: String with the most accessed endpoint and count
    :param suspicious_ips: DataFrame containing the suspicious IP addresses and failed login counts
    :return: None
    """
    # Start with an empty CSV file or overwrite the existing file
    with open("log_analysis_results.csv", mode='w', newline='') as file:
        # Write the "Requests per IP" section
        ip_counts_sorted.to_csv(file, index=False, header=True)
        
        file.write("\n")

        # Write the "Most Accessed Endpoint" section
        # Parse the most accessed endpoint and count
        endpoint, count_str = most_frequent.replace("Most Frequently Accessed Endpoint:\n", "").split(" (Accessed ")
        count = int(count_str.replace(" times)", ""))
        
        most_frequent_df = pd.DataFrame([[endpoint, count]], columns=["Endpoint", "Access Count"])
        most_frequent_df.to_csv(file, index=False, header=True)
        
        file.write("\n")
        
        # Write the "Suspicious Activity" section
        if not suspicious_ips.empty:
            suspicious_ips.to_csv(file, index=False, header=True)


def main():
    """
    Main function to parse the log file, analyze the request counts by IP, identify the most 
    frequently accessed endpoint, and detect suspicious activity based on failed login attempts.
    """
    log_file_path = "sample.log"
    log_df = parse_log_file(log_file_path)

    ip_counts_sorted = count_requests_by_ip(log_df)
    print("IP Request Counts:")
    print(ip_counts_sorted.to_string(index=False))
    print()

    most_frequent = most_frequent_endpoint(log_df)
    print(most_frequent)
    print()

    suspicious_ips = detect_suspicious_activity(log_df, threshold=1)
    if suspicious_ips is not None:
        print("Suspicious Activity Detected:")
        print(suspicious_ips.to_string(index=False))
    else:
        print("No suspicious activity detected.")
    
    save_results_to_csv(ip_counts_sorted, most_frequent, suspicious_ips)

if __name__ == "__main__":
    main()
