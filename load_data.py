import pandas as pd
import glob
# Specify the directory where the CSV files are located
directory = '/Users/avinash/Documents/capstone Project/datasets/MachineLearningCVE'


# Use glob to get all CSV files in the directory and subdirectories
csv_files = glob.glob(f'{directory}/**/*.csv', recursive=True)

# Create an empty list to store dataframes
dfs = []

# Loop through each CSV file
for file in csv_files:
    try:
        # Try reading the CSV file
        df = pd.read_csv(file)
        # Only add non-empty dataframes to the list
        if not df.empty:
            dfs.append(df)
    except pd.errors.EmptyDataError:
        # Skip empty CSV files
        print(f"Skipping empty file: {file}")
    except Exception as e:
        # Handle other exceptions (e.g., permission issues)
        print(f"Error reading {file}: {e}")

# Optionally, concatenate them into one dataframe
combined_df=pd.DataFrame()
if dfs:
    combined_df = pd.concat(dfs, ignore_index=True)
    print(combined_df)
else:
    print("No valid CSV files to read.")

combined_df.columns = combined_df.columns.str.strip()



if 'Label' in combined_df.columns:
    combined_df['Label'], unique_mapping = pd.factorize(combined_df['Label'])
    print("Label column successfully updated.")
    print("Unique value mapping (original to new):", dict(enumerate(unique_mapping, start=1)))
else:
    print("The 'label' column does not exist in the combined dataframe.")


if 'Label' in combined_df.columns:
    unique_labels = combined_df['Label'].value_counts()
    print(unique_labels)
else:
    print("The 'label' column does not exist in the combined dataframe.")