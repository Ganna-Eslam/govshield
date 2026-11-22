import sys, os
sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "privacy-engine"))
from pipeline import protect, restore

if __name__ == "__main__":
    tests = [
        "حلل شكوى أحمد محمد، رقمه القومي 29012345678901، وتليفونه 01012345678",
        "كلمني على +201112345678 أو ahmed@gmail.com",
        "الرقم القومي ٢٩٠١٢٣٤٥٦٧٨٩٠١ والموبايل ٠١٠١٢٣٤٥٦٧٨",
        "التليفون 010 1234 5678",   # متوقع يفوت: ده اختبار ليكي
        "نص عادي مفيهوش حاجة",
                "موبايلي 010-1234-5678",
        "الرقم القومي 2901 2345 6789 01",
        "كلمني +20 111 234 5678",
                "المهندس كريم قال إن الموظفة منى اتأخرت",
        "اسمه سيد فتحي ومرتبه 5000",
        "قابلت على محمد في الشغل",
        "خالد وأحمد راحوا المدرسة",
        "نور الشمس جميلة النهاردة"
    ]
    for t in tests:
        r = protect(t)
        print("IN :", t)
        print("OUT:", r.get("safe_text", r))
        if r["status"] == "protected":
            print("BACK:", restore(r["safe_text"], r["mapping"]))
        print("-" * 60)