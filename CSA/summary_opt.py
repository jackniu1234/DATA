import json
import argparse
import copy
from pathlib import Path

def apply_mode_1(data):
    """
    模式一：流敏感性消除模式
    对于单条路径，store中如果有相同的item_region赋值，则只保留最后一次。
    """
    if "path_summary" not in data:
        return data

    for path in data["path_summary"]:
        state = path.get("program_state", {})
        store = state.get("store")
        
        if store is not None:
            # 字典去重：相同 item_region 的最后一次赋值会覆盖前面的
            deduped_store_dict = {}
            for item in store:
                deduped_store_dict[item["item_region"]] = item
            
            state["store"] = list(deduped_store_dict.values())
            
    return data

def apply_mode_2(data):
    """
    模式二：流敏感的路径敏感性消除
    将每条路径的约束变为 "constraints": null
    """
    if "path_summary" not in data:
        return data

    for path in data["path_summary"]:
        state = path.get("program_state", {})
        if "constraints" in state:
            state["constraints"] = None
            
    return data

def apply_mode_3(data):
    """
    模式三：流不敏感的路径敏感性消除
    """
    # 1. 先执行模式 1 和模式 2
    data = apply_mode_1(data)
    data = apply_mode_2(data)

    paths = data.get("path_summary", [])
    if not paths:
        return data

    # 2. 合并成一条路径
    merged_path = copy.deepcopy(paths[0])
    merged_path["id"] = "merged_path"

    # ==================== 处理 store 合并 ====================
    region_val_map = {}
    for path in paths:
        store = path.get("program_state", {}).get("store")
        if store:
            for item in store:
                region = item["item_region"]
                value = item["value"]
                if region not in region_val_map:
                    region_val_map[region] = set()
                region_val_map[region].add(value)

    merged_store = []
    for region, values in region_val_map.items():
        if len(values) > 1:
            # 冲突时，按照要求使用 UndefinedVal[]
            final_value = "UndefinedVal[]"
        else:
            final_value = list(values)[0]
        
        merged_store.append({
            "item_region": region,
            "value": final_value
        })

    merged_path["program_state"]["store"] = merged_store

    # ==================== 处理返回值合并 ====================
    def get_all_env_values(node):
        """递归获取 environment 树中所有的 'value' 字段值"""
        vals = []
        if isinstance(node, dict):
            for k, v in node.items():
                if k == "value" and isinstance(v, str):
                    vals.append(v)
                elif isinstance(v, (dict, list)):
                    vals.extend(get_all_env_values(v))
        elif isinstance(node, list):
            for item in node:
                vals.extend(get_all_env_values(item))
        return vals

    def set_env_values_to_undefined(node):
        """递归将 environment 树中所有的 'value' 字段值替换为 UndefinedVal[]"""
        if isinstance(node, dict):
            for k, v in node.items():
                if k == "value" and isinstance(v, str):
                    node[k] = "UndefinedVal[]"
                elif isinstance(v, (dict, list)):
                    set_env_values_to_undefined(v)
        elif isinstance(node, list):
            for item in node:
                set_env_values_to_undefined(item)

    ret_values = set()
    for path in paths:
        val = None
        # 提取 const_return_value
        if path.get("const_return_value") is not None:
            val = path.get("const_return_value")
        else:
            # 提取 environment 中的唯一值
            env = path.get("program_state", {}).get("environment", {})
            env_vals = get_all_env_values(env)
            if len(env_vals) == 1:
                val = env_vals[0]
        
        if val is not None:
            ret_values.add(val)

    # 如果存在不同的返回值（超过1个唯一值），则视为冲突，替换为 UndefinedVal[]
    if len(ret_values) > 1:
        if merged_path.get("const_return_value") is not None:
            merged_path["const_return_value"] = "UndefinedVal[]"
        else:
            # 修改 merged_path 中的 environment 值
            env = merged_path.get("program_state", {}).get("environment", {})
            env_vals = get_all_env_values(env)
            if len(env_vals) == 1:
                set_env_values_to_undefined(env)

    # ==================== 处理 checker_messages 合并 ====================
    unique_messages = []
    seen_messages = set()
    
    for path in paths:
        msgs = path.get("checker_messages")
        if msgs:
            for msg in msgs:
                msg_str = json.dumps(msg, sort_keys=True)
                if msg_str not in seen_messages:
                    seen_messages.add(msg_str)
                    unique_messages.append(msg)

    merged_path["checker_messages"] = unique_messages if unique_messages else None

    # 将合并后的单条路径写回数据中
    data["path_summary"] = [merged_path]
    return data

def process_single_file(input_file: Path, output_file: Path, mode: int):
    """处理单个 JSON 文件"""
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            data = json.load(f)

        if mode == 1:
            data = apply_mode_1(data)
        elif mode == 2:
            data = apply_mode_2(data)
        elif mode == 3:
            data = apply_mode_3(data)

        # 确保输出文件的父目录存在
        output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            
        print(f"[成功] {input_file.name} -> {output_file}")
    except Exception as e:
        print(f"[失败] 处理文件 {input_file.name} 时出错: {e}")

def main():
    parser = argparse.ArgumentParser(description="批处理程序路径摘要 JSON 数据。")
    parser.add_argument("-i", "--input", required=True, help="输入的 JSON 文件或【文件夹】路径")
    parser.add_argument("-o", "--output", required=True, help="输出的 JSON 文件或【文件夹】路径")
    parser.add_argument("-m", "--mode", type=int, choices=[1, 2, 3], required=True, 
                        help="处理模式: 1(流敏感性消除), 2(流敏感的路径敏感性消除), 3(流不敏感的路径敏感性消除)")

    args = parser.parse_args()

    in_path = Path(args.input)
    out_path = Path(args.output)

    if not in_path.exists():
        print(f"错误：输入路径不存在 -> {in_path}")
        return

    # 情况 A：输入是文件夹 -> 进行批处理
    if in_path.is_dir():
        out_path.mkdir(parents=True, exist_ok=True)
        json_files = list(in_path.glob("*.json"))
        if not json_files:
            print(f"警告：在目录 {in_path} 中没有找到任何 .json 文件。")
            return
            
        print(f"开始批处理目录 {in_path}，共发现 {len(json_files)} 个 JSON 文件 (模式 {args.mode})...")
        for json_file in json_files:
            target_file = out_path / json_file.name
            process_single_file(json_file, target_file, args.mode)
            
        print("批处理完成！")

    # 情况 B：输入是单个文件 -> 处理单个文件
    elif in_path.is_file():
        if out_path.is_dir():
            target_file = out_path / in_path.name
        else:
            target_file = out_path
            
        print(f"开始处理单个文件: {in_path.name} (模式 {args.mode})...")
        process_single_file(in_path, target_file, args.mode)
        print("处理完成！")

if __name__ == "__main__":
    main()

# python process_summary.py -i input_jsons -o output_jsons -m 3
# python process_summary.py -i input_jsons/test1.json -o output_jsons/test1_processed.json -m 1