import docx
import re
import sys

def extract_abbreviations(file_path, output_path):
    doc = docx.Document(file_path)
    
    text = "\n".join([para.text for para in doc.paragraphs])
    
    # Pattern 1: Capitalized word(s) followed by (ABBREVIATION)
    pattern1 = re.compile(r'((?:[A-Z][A-Za-z0-9\-&]+|[a-zđĐáàảãạăắằẳẵặâấầẩẫậéèẻẽẹêếềểễệíìỉĩịóòỏõọôốồổỗộơớờởỡợúùủũụưứừửữựýỳỷỹỵ]+)(?:\s+(?:[A-Z][A-Za-z0-9\-&]+|[a-zđĐáàảãạăắằẳẵặâấầẩẫậéèẻẽẹêếềểễệíìỉĩịóòỏõọôốồổỗộơớờởỡợúùủũụưứừửữựýỳỷỹỵ]+)){0,6})\s*\(([A-Z0-9\-&]{2,})\)')
    
    # Pattern 2: (ABBREVIATION) - to catch orphans
    pattern2 = re.compile(r'\(([A-Z0-9\-&]{2,})\)')
    
    # Pattern 3: general uppercase words
    pattern3 = re.compile(r'\b[A-Z0-9\-&]{2,}\b')
    
    matches1 = pattern1.findall(text)
    
    abbr_dict = {}
    for phrase, abbr in matches1:
        abbr_dict[abbr] = phrase.strip()
        
    all_abbrs = pattern2.findall(text) + pattern3.findall(text)
    # filter out numbers
    all_abbrs = [a for a in all_abbrs if not a.isdigit() and re.search(r'[A-Z]', a)]
    
    unique_abbrs = set(all_abbrs)
    
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("=== ABBREVIATIONS WITH CONTEXT ===\n")
        for abbr, phrase in sorted(abbr_dict.items()):
            f.write(f"{abbr}: {phrase}\n")
            
        f.write("\n=== OTHER POSSIBLE ABBREVIATIONS ===\n")
        for abbr in sorted(unique_abbrs):
            if abbr not in abbr_dict:
                context_match = re.search(r'(.{0,40})\b' + re.escape(abbr) + r'\b(.{0,40})', text)
                if context_match:
                    f.write(f"{abbr}: ...{context_match.group(1).strip()} {abbr} {context_match.group(2).strip()}...\n")
                else:
                    f.write(f"{abbr}\n")

if __name__ == "__main__":
    extract_abbreviations("e:\\u_a_u_o\\NCKH (1).docx", "e:\\u_a_u_o\\temp_abbr_output.txt")
