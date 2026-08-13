import json

def process_user_data(user_dict: dict) -> dict:
    """
    Cleans and processes a dictionary of user data.
    """
    if not isinstance(user_dict, dict):
        return {}
        
    cleaned_data = {}
    
    # Process basic fields
    if "username" in user_dict:
        cleaned_data["username"] = str(user_dict["username"]).strip().lower()
        
    if "email" in user_dict:
        cleaned_data["email"] = str(user_dict["email"]).strip().lower()
        
    # Process metadata if present
    if "metadata" in user_dict and isinstance(user_dict["metadata"], dict):
        cleaned_data["metadata"] = {}
        for key, value in user_dict["metadata"].items():
            if isinstance(key, str) and isinstance(value, (str, int, bool)):
                cleaned_data["metadata"][key] = value
                
    return cleaned_data

def load_and_process(json_string: str) -> dict:
    try:
        data = json.loads(json_string)
        return process_user_data(data)
    except json.JSONDecodeError:
        return {}
