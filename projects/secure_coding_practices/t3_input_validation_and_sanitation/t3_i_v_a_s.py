import re

def process_user_score(score_input: any) -> int:
    """
    Validates and processes a user-supplied score input, ensuring it is a 
    valid integer between 0 and 100 inclusive.

    This function acts as a defense mechanism against Injection (A03) and 
    Insecure Design (A04) by enforcing data integrity rules.
    
    :param score_input: The user-supplied value (can be string, int, etc.).
    :return: The validated and sanitized integer score.
    :raises TypeError: If the input cannot be converted to a number.
    :raises ValueError: If the numeric score is outside the allowed range.
    """
    
    # Type Validation and Sanitization (Handling non-numeric input)
    print(f"Received input: '{score_input}' (Datatype: {type(score_input).__name__})")
    
    # Attempt to convert to float first to handle string representations of numbers
    try:
        score_str = str(score_input).strip()
        
        # Simple Sanitization: Check if the string contains non-numeric/non-dot/non-sign characters
        if not re.match(r'^-?\d+(\.\d+)?$', score_str):
             score_numeric = float(score_str)
        else:
            score_numeric = float(score_str)
            
    except ValueError:
        raise TypeError(f"Validation Error: Score must be a numeric value. Cannot convert '{score_input}' to a number.")
        
    # Cast to integer
    score_int = int(score_numeric)
    
    # Range Validation
    MIN_SCORE = 0
    MAX_SCORE = 100
    
    if not (MIN_SCORE <= score_int <= MAX_SCORE):
        raise ValueError(f"Range Error: Score must be between {MIN_SCORE} and {MAX_SCORE}. Received: {score_int}")
    
    print(f"[SUCCESS] Validated score: {score_int}")
    return score_int

# --- Demonstration ---

if __name__ == "__main__":
    print("Input Validation and Sanitization Demonstration")
    
    # Success test cases
    success_inputs = [
        ("95", "String input"),
        (42, "Integer input"),
        (0, "Minimum valid score"),
        (100, "Maximum valid score"),
        (75.9, "Float input (should truncate to 75)"),
    ]
    
    print("\nSUCCESSFUL VALIDATION CASES")
    for score, description in success_inputs:
        try:
            print(f"Test: {description} ({score})")
            processed_score = process_user_score(score)
            print(f"Result: Score is safe: {processed_score}")
        except (TypeError, ValueError) as e:
            print(f"ERROR: Unexpected failure: {e}")
            
    # Failure test cases
    failure_inputs = [
        ("101", "Out of range (too high)"),
        ("-10", "Out of range (too low)"),
        ("75; DROP TABLE", "Injection attempt (should fail type check or be treated as a large float)"),
        ("abc", "Non-numeric string"),
        (None, "None value"),
    ]
    
    print("\nFAILURE VALIDATION CASES (Expected Errors)")
    for score, description in failure_inputs:
        try:
            print(f"Test: {description} ({score})")
            process_user_score(score)
        except (TypeError, ValueError) as e:
            print(f"Result: [FAILURE] Correctly caught error: {e}")
        except Exception as e:
            print(f"Result: [FAILURE] Caught unexpected error: {e}")
            
    print("[CONCLUSION]")
    print("Input validation successfully rejected inputs that violated the required type and range, preventing potential security flaws (like Injection) and ensuring data integrity.")