import docx
import os

def extract_section(directory):
    target_file = os.path.join(directory, "CHƯƠNG 3.docx")
            
    if not os.path.exists(target_file):
        print("File not found")
        return
        
    doc = docx.Document(target_file)
    in_section = False
    
    with open(os.path.join(directory, "temp_output_utf8.txt"), "w", encoding="utf-8") as f:
        for para in doc.paragraphs:
            text = para.text.strip()
            if text.startswith("3.4.4"):
                in_section = True
            elif text.startswith("3.4.5") or text.startswith("3.5"):
                if in_section:
                    break
            
            if in_section and text:
                f.write(text + "\n")

if __name__ == "__main__":
    extract_section("e:\\u_a_u_o")
