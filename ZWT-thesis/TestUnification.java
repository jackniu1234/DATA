/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
//@category Examples

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonSyntaxException;

import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraState;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.program.database.ProgramContentHandler;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;

public class TestUnification extends GhidraScript {

    // 脚本配置
    private static String SUBSCRIPT_NAME = "unification-gcc.py";
    private static String taskPath = "/home/jackniu/scripts/spec-gcc/tasks.csv";
    private static String resultPath = "/home/jackniu/scripts/spec-gcc/result.csv";

    // [新增] Ground Truth 文件所在的基础目录，请根据实际情况修改
    // 假设文件名为 {name}.json，例如 400.perlbench.json
    private static String gtBasePath = "/home/jackniu/scripts/spec-gcc/ground_truth/";

    /**
     * 核心比较逻辑
     */
    public static void compareNameAndNumber(String inputFilePath) throws IOException {
        // 备份旧结果
        if (Files.exists(Path.of(resultPath))) {
            Files.copy(Path.of(resultPath), Path.of(resultPath + ".backup"), StandardCopyOption.REPLACE_EXISTING);
        }

        PrintWriter writer = new PrintWriter(new FileWriter(resultPath));
        // [修改] 增加 precision 和 recall 列
        writer.println("program,all,resolved,time,AICT,FuncNum,AnalysisFuncNum,precision,recall");

        try (BufferedReader reader = new BufferedReader(new FileReader(inputFilePath))) {
            String line;
            int lineNumber = 0;

            while ((line = reader.readLine()) != null) {
                lineNumber++;
                line = line.trim();
                if (line.isEmpty()) continue;

                String name = line;

                // 1. 构建 Result JSON 路径 (Prediction)
                String predJsonFilePath = String.format("/home/jackniu/scripts/spec-gcc/%s/result.json", name);
                String gtJsonFilePath = String.format("/home/jackniu/scripts/spec-gcc/%s/gt.json", name);

                String allNumber = "0";
                String actualNumber = "0";
                String time = "0";
                String AICT = "0";
                String FuncNum = "0";
                String AnalysisFuncNum = "0";
                double precision = 0.0;
                double recall = 0.0;

                // 处理 Prediction 文件
                String predJsonContent = null;
                try {
                    if (Files.exists(Paths.get(predJsonFilePath))) {
                        predJsonContent = new String(Files.readAllBytes(Paths.get(predJsonFilePath)));

                        // 提取基础信息 (保留原有逻辑)
                        actualNumber = extractValue(predJsonContent, "resolved");
                        allNumber = extractValue(predJsonContent, "all");
                        AnalysisFuncNum = extractValue(predJsonContent, "processed_nums");
                        FuncNum = extractValue(predJsonContent, "total_functions");
                        time = extractValue(predJsonContent, "time");
                        AICT = extractValue(predJsonContent, "AICT");
                    } else {
                        System.out.println("警告: 结果文件不存在: " + predJsonFilePath);
                    }
                } catch (IOException e) {
                    System.out.println("错误: 无法读取结果文件: " + predJsonFilePath);
                }

                // 处理 Ground Truth 并计算指标
                if (predJsonContent != null && Files.exists(Paths.get(gtJsonFilePath))) {
                    try {
                        String gtJsonContent = new String(Files.readAllBytes(Paths.get(gtJsonFilePath)));
                        double[] metrics = calculateMetrics(predJsonContent, gtJsonContent);
                        precision = metrics[0];
                        recall = metrics[1];
                    } catch (Exception e) {
                        System.out.println("错误: 计算指标时出错 (" + name + "): " + e.getMessage());
                        e.printStackTrace();
                    }
                } else {
                    if (!Files.exists(Paths.get(gtJsonFilePath))) {
                         System.out.println("提示: GT文件不存在，跳过指标计算: " + gtJsonFilePath);
                    }
                }

                // [修改] 写入包含指标的结果
                writer.printf("%s,%s,%s,%s,%s,%s,%s,%.4f,%.4f\n", name, allNumber, actualNumber, time, AICT, FuncNum, AnalysisFuncNum, precision, recall);
                writer.flush();
            }

        } catch (IOException e) {
            System.out.println("错误: 无法读取输入任务文件: " + inputFilePath + " - " + e.getMessage());
        }

        writer.close();
        System.out.println("统计完成，结果已写入: " + resultPath);
    }

    /**
     * [新增] 计算 Precision 和 Recall
     * 返回 double[]{precision, recall}
     */
    private static double[] calculateMetrics(String predJson, String gtJson) {
        Gson gson = new Gson();

        Set<String> predEdges = new HashSet<>();
        Set<String> gtEdges = new HashSet<>();

        try {
            // 解析 Prediction
            JsonObject predObj = gson.fromJson(predJson, JsonObject.class);
            extractEdgesPred(predObj, predEdges);

            // 解析 Ground Truth
            JsonObject gtObj = gson.fromJson(gtJson, JsonObject.class);
            extractEdgesGt(gtObj, gtEdges);

            // 集合运算
            // TP: 交集
            Set<String> tpSet = new HashSet<>(predEdges);
            tpSet.retainAll(gtEdges);
            int tp = tpSet.size();

            // FP: Pred - GT
            int fp = predEdges.size() - tp;

            // FN: GT - Pred
            int fn = gtEdges.size() - tp;

            // 计算指标
            double precision = (tp + fp) > 0 ? (double) tp / (tp + fp) : 0.0;
            double recall = (tp + fn) > 0 ? (double) tp / (tp + fn) : 0.0;

            return new double[]{precision, recall};

        } catch (JsonSyntaxException e) {
            System.err.println("JSON 解析失败: " + e.getMessage());
            return new double[]{0.0, 0.0};
        }
    }

    /**
     * [新增] 从 Prediction JSON 中提取边
     * 格式: { "0xSite": { "target": ["0xTgt1", ...] } }
     */
    private static void extractEdgesPred(JsonObject root, Set<String> edges) {
        if (root == null) return;
        for (Map.Entry<String, JsonElement> entry : root.entrySet()) {
            Long src = normalizeHex(entry.getKey());
            if (src == null) continue;

            if (entry.getValue().isJsonObject()) {
                JsonObject content = entry.getValue().getAsJsonObject();
                if (content.has("target") && content.get("target").isJsonArray()) {
                    JsonArray targets = content.getAsJsonArray("target");
                    for (JsonElement tgt : targets) {
                        Long dst = normalizeHex(tgt.getAsString());
                        if (dst != null) {
                            edges.add(src + "->" + dst);
                        }
                    }
                }
            }
        }
    }

    /**
     * [新增] 从 Ground Truth JSON 中提取边
     * 格式: { "0xSite": ["0xTgt1", ...] }
     */
    private static void extractEdgesGt(JsonObject root, Set<String> edges) {
        if (root == null) return;
        for (Map.Entry<String, JsonElement> entry : root.entrySet()) {
            Long src = normalizeHex(entry.getKey());
            if (src == null) continue;

            if (entry.getValue().isJsonArray()) {
                JsonArray targets = entry.getValue().getAsJsonArray();
                for (JsonElement tgt : targets) {
                    Long dst = normalizeHex(tgt.getAsString());
                    if (dst != null) {
                        edges.add(src + "->" + dst);
                    }
                }
            }
        }
    }

    /**
     * [新增] 归一化十六进制字符串为 Long，用于准确比较
     */
    private static Long normalizeHex(String hexStr) {
        if (hexStr == null) return null;
        hexStr = hexStr.trim();
        if (hexStr.startsWith("0x") || hexStr.startsWith("0X")) {
            hexStr = hexStr.substring(2);
        }
        try {
            return Long.parseUnsignedLong(hexStr, 16);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /**
     * 从JSON字符串中提取简单字段的值 (保留原有的轻量级解析用于 extracting resolved/all/time)
     */
    private static String extractValue(String jsonContent, String header) {
        String searchPattern = String.format("\"%s\"", header);
        int resolvedIndex = jsonContent.indexOf(searchPattern);
        if (resolvedIndex == -1) return null;

        int colonIndex = jsonContent.indexOf(":", resolvedIndex);
        if (colonIndex == -1) return null;

        int valueStart = colonIndex + 1;
        while (valueStart < jsonContent.length() && Character.isWhitespace(jsonContent.charAt(valueStart))) {
            valueStart++;
        }
        if (valueStart >= jsonContent.length()) return null;

        char valueStartChar = jsonContent.charAt(valueStart);
        int valueEnd;
        String resolvedValue;

        if (valueStartChar == '"') {
            valueEnd = jsonContent.indexOf("\"", valueStart + 1);
            if (valueEnd == -1) return null;
            resolvedValue = jsonContent.substring(valueStart + 1, valueEnd);
        } else {
            valueEnd = valueStart + 1;
            while (valueEnd < jsonContent.length()) {
                char c = jsonContent.charAt(valueEnd);
                if (c == ',' || c == '}' || c == ']' || Character.isWhitespace(c)) break;
                valueEnd++;
            }
            resolvedValue = jsonContent.substring(valueStart, valueEnd).trim();
        }
        return resolvedValue;
    }

    @Override
    public void run() throws Exception {
        if (currentProgram != null) {
            popup("This script should be run from a tool with no open programs");
            return;
        }

        Project project = state.getProject();
        ProjectData projectData = project.getProjectData();
        DomainFolder rootFolder = projectData.getRootFolder();
        recurseProjectFolder(rootFolder);

        // 执行完成后进行统计
        compareNameAndNumber(taskPath);
    }

    private void recurseProjectFolder(DomainFolder domainFolder) throws CancelledException, IOException {
        DomainFile[] files = domainFolder.getFiles();
        Arrays.sort(files, new Comparator<DomainFile>() {
            @Override
            public int compare(DomainFile file1, DomainFile file2) {
                return file1.getName().toLowerCase().compareTo(file2.getName().toLowerCase());
            }
        });

        for (DomainFile domainFile : files) {
            String fileName = domainFile.getName();
            if ("perlbench-gcc-O2".equals(fileName)) {
                continue;
            }
            processDomainFile(domainFile);
        }
    }

    private void processDomainFile(DomainFile domainFile) throws CancelledException, IOException {
        if (!ProgramContentHandler.PROGRAM_CONTENT_TYPE.equals(domainFile.getContentType())) {
            return;
        }
        if (domainFile.isVersioned() && !domainFile.isCheckedOut()) {
            println("WARNING! Skipping versioned file - not checked-out: " + domainFile.getPathname());
            return;
        }
        Program program = null;
        try {
            program = (Program) domainFile.getDomainObject(this, true, false, monitor);
            processProgram(program);
            saveProgram(program);
        } catch (Exception e) {
            println("ERROR! Failed to process file due to upgrade issue: " + domainFile.getPathname());
        } finally {
            if (program != null) {
                program.release(this);
            }
        }
    }

    private void processProgram(Program program) throws CancelledException, IOException {
        println("Processing: " + program.getDomainFile().getPathname());
        monitor.setMessage("Processing: " + program.getDomainFile().getName());
        int id = program.startTransaction("Batch Script Transaction");
        try {
            GhidraState newState = new GhidraState(state.getTool(), state.getProject(), program, null, null, null);
            runScript(SUBSCRIPT_NAME, newState);
        } catch (Exception e) {
            printerr("ERROR! Exception occurred while processing file: " + program.getDomainFile().getPathname());
            printerr("       " + e.getMessage());
            e.printStackTrace();
        } finally {
            program.endTransaction(id, true);
        }
    }
}