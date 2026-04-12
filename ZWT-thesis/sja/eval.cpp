#include <iostream>
#include <fstream>
#include <sstream>
#include <utility>
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <string> // 确保包含 string
using namespace std;

#define IMM uint64_t
#define hex_to_int(s) stoull(s, nullptr, 16)
#define dec_to_int(s) stoull(s, nullptr, 10)

double LO = 0;
double HI = 0;

/* ------------------------------- jump tables ------------------------------ */
struct TargetExpr {
   IMM base;
   IMM stride;
   IMM entry_size;
   IMM table_size;
   unordered_set<IMM> targets;
};

bool hex_mode = false;
string dir = "";
string custom_result_path = ""; // [新增] 用于存储你的结果文件路径
string prev_dir = "";

// [新增] 存放你的结果的数据结构
unordered_map<IMM,TargetExpr> jtable_custom;

unordered_map<IMM,TargetExpr> jtable_gt;
unordered_map<IMM,TargetExpr> jtable_sba;
unordered_map<IMM,TargetExpr> jtable_angr;
unordered_map<IMM,TargetExpr> jtable_dyninst;
unordered_map<IMM,TargetExpr> jtable_ghidra;
unordered_map<IMM,TargetExpr> jtable_ddisasm;
unordered_set<IMM> indirect_jumps;
unordered_map<IMM,IMM> jump_block;
unordered_map<IMM,unordered_set<IMM>> gt_base_jump;
unordered_map<IMM,unordered_set<IMM>> sba_base_jump;
unordered_map<IMM,unordered_set<IMM>> sba_base_targets;

bool verify_jumps(IMM jump_loc, const unordered_set<IMM>& targets_m) {
   if (!indirect_jumps.contains(jump_loc))
      return false;
   auto it = jtable_gt.find(jump_loc);
   if (it == jtable_gt.end())
      // return !targets_m.empty();
      return false;
   IMM cnt = 0;
   auto const& targets_gt = it->second.targets;
   for (auto t: targets_gt)
      cnt += targets_m.contains(t)? 1: 0;
   return cnt != 0;
}

void scan_jumps() {
   string s;
   fstream f(dir + "obj.s", fstream::in);
   while (getline(f,s)) {
      size_t p = 0;
      size_t p1 = 0;
      size_t p2 = 0;
      IMM d = 0;
      do {
         p2 = s.find(">",p1);
         p1 = s.find("<",p1);
         if (p1 < p2) {
            ++d;
            if (d == 1)
               p = p1;
            p1 = p1+1;
         }
         else if (p2 < p1) {
            --d;
            p1 = p2+1;
            if (d == 0) {
               s.erase(p, p2-p+1);
               p1 = 0;
            }
         }
         else
            break;
      }
      while (true);
      p = s.find("jmp");
      if (p != string::npos && s.find("*",p) != string::npos
      && s.find("%rip") == string::npos) {
         p = s.find_first_not_of("0");
         indirect_jumps.insert(hex_to_int("0x" + s.substr(p,s.find(" ")-p)));
      }
   }
   f.close();
}


void load_jtable_gt() {
   string s;
   fstream f(dir + "log.gt", fstream::in);
   IMM jump_loc = 0;
   IMM table_size = 0;
   IMM base = 0;
   IMM entry_size = 0;
   IMM block = 0;
   unordered_set<IMM> targets;

   std::ofstream csv_file(dir+"gt_standard.csv");
   csv_file << "jump_loc,base,entry_size,table_size" << std::endl;

   while (getline(f,s)) {
      if (s.find("entry number is") != string::npos) {
         auto p = s.find("entry number is") + 16;
         auto p2 = s.find(",", p);
         table_size = dec_to_int(s.substr(p, p2-p));
         block = hex_to_int(s.substr(p2+16, string::npos));
      }
      else if (s.find("INFO:Jump table base is") != string::npos)
         base = hex_to_int(s.substr(24, string::npos));
      else if (s.find("INFO:[indirect instruction]") != string::npos) {
         auto p = s.find(":", 28);
         jump_loc = hex_to_int(s.substr(28, p-28));
      }
      else if (s.find("INFO:entry size is ") != string::npos)
         entry_size = hex_to_int(s.substr(19, string::npos));
      else if (s.find("INFO:Entry#") != string::npos) {
         auto p = s.find(" ", s.find(" ",11)+1)+1;
         targets.insert(dec_to_int(s.substr(p, string::npos)));
      }
      if (jump_loc != 0 && indirect_jumps.contains(jump_loc)
      && s.find("INFO:JMPTBL entry") != string::npos) {
         gt_base_jump[base].insert(jump_loc);
         jtable_gt[jump_loc] = TargetExpr{base, entry_size, entry_size, table_size, targets};
         jump_block[jump_loc] = block;


         csv_file << std::hex << jump_loc << ","
                  << base << std::dec << ","
                  << entry_size << ","
                  << table_size << std::endl;


         block = -1;
         jump_loc = -1;
         base = 0;
         entry_size = 0;
         targets.clear();
      }
   }
   f.close();
   csv_file.close();
}


void load_jtable_sba() {
   string s;
   IMM t = 0;
   IMM jump_loc = 0;
   IMM base = 0;
   unordered_set<IMM> targets;

   fstream f_icf(dir + "sba.icf", fstream::in);
   while (getline(f_icf,s)) {
      stringstream ss;
      ss << s;
      ss >> jump_loc;
      targets.clear();
      while (ss >> t)
         targets.insert(t);
      if (verify_jumps(jump_loc, targets))
         jtable_sba[jump_loc] = TargetExpr{0, 0, 0, targets.size(), targets};
   }
   f_icf.close();

   fstream f_jtable(dir + "sba.jtable", fstream::in);
   while (getline(f_jtable,s)) {
      stringstream ss;
      ss << s;
      ss >> base;
      targets.clear();
      while (ss >> t)
         targets.insert(t);
      sba_base_targets[base] = targets;
   }
   f_jtable.close();

   fstream f_base(dir + "sba.base", fstream::in);
   while (getline(f_base,s)) {
      stringstream ss;
      ss << s;
      ss >> jump_loc >> base;
      sba_base_jump[base].insert(jump_loc);
   }
   f_base.close();
}

// [新增] 加载你的结果文件的函数
void load_jtable_custom() {
   if (custom_result_path.empty())
      return;

   string s;
   IMM t = 0;
   IMM jump_loc = 0;
   IMM base = 0;
   unordered_set<IMM> targets;

   fstream f_icf(custom_result_path, fstream::in);
   while (getline(f_icf,s)) {
      stringstream ss;
      ss << s;
      ss >> std::hex >> jump_loc;
      targets.clear();
      while (ss >> t) {
         targets.insert(t);
      }
      if (verify_jumps(jump_loc, targets))
         jtable_custom[jump_loc] = TargetExpr{0, 0, 0, targets.size(), targets};
   }
   f_icf.close();
}


void load_jtable_angr() {
   string s;
   IMM b = 0;
   IMM jump_loc = -1;
   unordered_set<IMM> targets;
   fstream f(dir + "log.angr", fstream::in);
   while (getline(f,s)) {
      auto p = s.find("instruction:");
      if (p != string::npos) {
         if (verify_jumps(jump_loc, targets)) {
            jtable_angr[jump_loc] = TargetExpr{0, 0, 0, targets.size(), targets};
            jump_loc = -1;
         }
         auto s2 = s.substr(13, string::npos);
         if (s2.length() < 10)
            jump_loc = dec_to_int(s2);
         targets.clear();
         continue;
      }
      p = s.find("Edge");
      if (p != string::npos) {
         p = s.find("->") + 3;
         auto s2 = s.substr(p, string::npos);
         if (s2.length() < 10)
            targets.insert(dec_to_int(s.substr(p, string::npos)));
         continue;
      }
   }
   f.close();
}


void load_jtable_dyninst() {
   string s;
   IMM jump_loc = -1;
   unordered_set<IMM> targets;
   fstream f(dir + "log.dyninst", fstream::in);
   while (getline(f,s)) {
      auto p = s.find("Get instruction Addr:");
      if (p != string::npos) {
         jump_loc = dec_to_int(s.substr(p+22,string::npos));
         targets.clear();
         continue;
      }
      p = s.find("Get edge:");
      if (p != string::npos) {
         p = s.find("->", p) + 3;
         auto s2 = s.substr(p,string::npos);
         if (s2.compare("18446744073709551615") != 0) {
            auto t = dec_to_int(s2);
            targets.insert(t);
            continue;
         }
      }
      if (verify_jumps(jump_loc, targets)) {
         jtable_dyninst[jump_loc] = TargetExpr{0, 0, 0, targets.size(), targets};
         jump_loc = -1;
         targets.clear();
      }
   }
   if (verify_jumps(jump_loc, targets))
      jtable_dyninst[jump_loc] = TargetExpr{0, 0, 0, targets.size(), targets};
   f.close();
}


void load_jtable_ghidra() {
   string s;
   IMM jump_loc = 0;
   unordered_set<IMM> targets;
   fstream f(dir + "log.ghidra", fstream::in);
   while (getline(f,s)) {
      auto p = s.find("Basic block address:");
      if (p != string::npos) {
         if (verify_jumps(jump_loc, targets))
            jtable_ghidra[jump_loc] = TargetExpr{0, 0, 0, targets.size(), targets};
         jump_loc = dec_to_int(s.substr(p+21,string::npos));
         targets.clear();
         continue;
      }
      p = s.find("Instruction address:");
      if (p != string::npos) {
         if (verify_jumps(jump_loc, targets))
            jtable_ghidra[jump_loc] = TargetExpr{0, 0, 0, targets.size(), targets};
         jump_loc = dec_to_int(s.substr(p+21,string::npos));
         targets.clear();
         continue;
      }
      p = s.find("Successor:");
      if (p != string::npos) {
         targets.insert(dec_to_int(s.substr(p+11,string::npos)));
         continue;
      }
   }
   f.close();
}


void load_jtable_ddisasm() {
   string s = "";
   unordered_map<IMM,unordered_set<IMM>> ddisasm_info;
   fstream f(dir + "log.ddisasm", fstream::in);
   while (getline(f,s)) {
      auto p = s.find(" ");
      auto src = dec_to_int(s.substr(0, p));
      auto dst = dec_to_int(s.substr(p+1,string::npos));
      ddisasm_info[src].insert(dst);
   }
   f.close();

   for (auto const& [jump_loc, expr]: jtable_gt) {
      auto src = jump_block[jump_loc];
      if (ddisasm_info.contains(src)) {
         auto const& targets = ddisasm_info.at(src);
         if (verify_jumps(jump_loc, targets))
            jtable_ddisasm[jump_loc] = TargetExpr{0, 0, 0, targets.size(), targets};
      }
   }
}


void eval_jtable(const string& s, const unordered_map<IMM,TargetExpr>& m, const string& outfile) {
   fstream f(outfile, fstream::out);
   IMM jtentry = 0;
   IMM jtentry_correct = 0;
   IMM jtentry_over = 0;
   IMM jtentry_under = 0;
   IMM jtbase_correct = 0;
   unordered_map<IMM, unordered_set<IMM>> gt_base_targets;
   unordered_map<IMM, unordered_set<IMM>> m_base_targets;

   for (auto const& [base, jumps]: gt_base_jump) {
      for (auto jump: jumps) {
         gt_base_targets[base].insert(jtable_gt.at(jump).targets.begin(), jtable_gt.at(jump).targets.end());
         if (m.contains(jump))
            m_base_targets[base].insert(m.at(jump).targets.begin(), m.at(jump).targets.end());
      }
      if (&m == &jtable_sba && sba_base_targets.contains(base))
         m_base_targets[base].insert(sba_base_targets.at(base).begin(),sba_base_targets.at(base).end());
   }

   f << "Evaluate " << s << " ... \n";
   f << "-----------------------------------\n";
   f << "        jtable_entry_under         \n";
   f << "-----------------------------------\n";
   if (s == "my_method") {
      std::cout << "hello\n";
   }

   for (auto const& [base, gt_targets]: gt_base_targets) {
      auto& m_targets = m_base_targets[base];
      IMM correct = 0;
      IMM under = 0;
      IMM over = 0;
      for (auto x: gt_targets)
         if (!m_targets.contains(x))
            ++under;
         else
            ++correct;
      for (auto x: m_targets) {
         if (!gt_targets.contains(x)) {
            ++over;
            if (s == "my_method") {
               std::cout << std::hex << base << ' ' <<  x << '\n';
            }
         }

      }
      if (under > 0) {
         f << "base\t\ttotal\tcorrect\tover\tunder\n";
         if (hex_mode)
            f << std::hex << base << std::dec << "\t\t" << gt_targets.size() << "\t\t" << correct << "\t\t" << over << "\t\t" << under << "\n";
         else
            f << std::dec << base << std::dec << "\t\t" << gt_targets.size() << "\t\t" << correct << "\t\t" << over << "\t\t" << under << "\n";
         f << "jumps\n";
         for (auto jump: gt_base_jump.at(base))
            if (hex_mode)
               f << std::hex << jump << " ";
            else
               f << std::dec << jump << " ";
         f << "\n";
         f << "-----------------------------------\n";
      }
      jtentry += gt_targets.size();
      jtentry_under += under;
      jtentry_correct += correct;
      /* handle jtbase */
      if ((double)correct >= LO*(double)(gt_targets.size()) &&
          (double)(over+correct) <= HI*(double)(gt_targets.size()))
            jtbase_correct += 1;
   }
   f << "\n\n";
   f << "-----------------------------------\n";
   f << "        jtable_entry_over          \n";
   f << "-----------------------------------\n";
   for (auto const& [base, gt_targets]: gt_base_targets) {
      auto& m_targets = m_base_targets[base];
      IMM correct = 0;
      IMM under = 0;
      IMM over = 0;
      for (auto x: gt_targets)
         if (!m_targets.contains(x))
            ++under;
         else
            ++correct;
      for (auto x: m_targets)
         if (!gt_targets.contains(x))
            ++over;
      if (over > 0) {
         f << "base\t\ttotal\tcorrect\tover\tunder\n";
         if (hex_mode)
            f << std::hex << base << std::dec << "\t\t" << gt_targets.size() << "\t\t" << correct << "\t\t" << over << "\t\t" << under << "\n";
         else
            f << std::dec << base << std::dec << "\t\t" << gt_targets.size() << "\t\t" << correct << "\t\t" << over << "\t\t" << under << "\n";
         f << "jumps\n";
         for (auto jump: gt_base_jump.at(base))
            if (hex_mode)
               f << std::hex << jump << " ";
            else
               f << std::dec << jump << " ";
         f << "\n";
         f << "-----------------------------------\n";
      }
      jtentry_over += over;
   }
   f << "\n\n";
   f << "-----------------------------------\n";
   f << "              summary              \n";
   f << "-----------------------------------\n";
   f << "#jtentry_gt: " << std::dec << jtentry << "\n";
   f << "#jtentry_correct_" << std::dec << s << ": " << jtentry_correct << "\n";
   f << "#jtentry_over_" << std::dec << s << ": " << jtentry_over << "\n";
   f << "#jtentry_under_" << std::dec << s << ": " << jtentry_under << "\n";
   f << "#jtbase_gt: " << std::dec << gt_base_targets.size() << "\n";
   f << "#jtbase_correct_" << std::dec << s << ": " << jtbase_correct << "\n";
   f.close();
}
/* -------------------------------------------------------------------------- */
int main(int argc, char** argv) {
   /* args */
   dir = string(argv[1]) + "/";
   hex_mode = (argc > 2 && string(argv[2]).compare("hex") == 0);
   {
      stringstream ss;
   ss << string(argv[3]);
   ss >> LO;
   }
   {
      stringstream ss;
   ss << string(argv[4]);
   ss >> HI;
   }

   // [新增] 获取第五个参数（如果存在），作为自定义结果文件的路径
   if (argc > 5) {
       custom_result_path = string(argv[5]);
   }

   /* load results */
   scan_jumps();
   load_jtable_gt();
   load_jtable_sba();
   // load_jtable_angr();
   load_jtable_dyninst();
   load_jtable_ghidra();
   // load_jtable_ddisasm();

   // [新增] 加载自定义结果
   load_jtable_custom();

   /* eval */
   eval_jtable("sba", jtable_sba, dir + "eval.sba");
   // eval_jtable("angr", jtable_angr, dir + "eval.angr");
   eval_jtable("dyninst", jtable_dyninst, dir + "eval.dyninst");
   eval_jtable("ghidra", jtable_ghidra, dir + "eval.ghidra");
   // eval_jtable("ddisasm", jtable_ddisasm, dir + "eval.ddisasm");

   // [新增] 评估自定义结果
   if (!jtable_custom.empty()) {
       eval_jtable("my_method", jtable_custom, dir + "eval.custom");
   }

   return 0;
}