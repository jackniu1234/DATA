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
// Shows how to run a script on all of the programs within the current project.
// NOTE: Script will only process unversioned and checked-out files.
//@category Examples

import java.io.IOException;
import java.io.PrintWriter;

import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraState;
import ghidra.framework.model.*;
import ghidra.program.database.ProgramContentHandler;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import java.util.Arrays;
import java.util.Comparator;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

public class TestEmtaintUnification extends GhidraScript {

	// The script referenced in the following line should be replaced with the script to be called
	private static String SUBSCRIPT_NAME = "unification-emtaint.py";
	private static String PRE_SUBSCRIPT_NAME = "find_icalls-emtaint.py";
    private static String taskPath = "/home/jackniu/scripts/emtaints/tasks.csv";
    private static String resultPath = "/home/jackniu/scripts/emtaints/result.csv";

    public static void compareNameAndNumber(String inputFilePath) throws IOException {
        Files.copy(Path.of(resultPath), Path.of(resultPath+".backup"), StandardCopyOption.REPLACE_EXISTING);
        PrintWriter writer = new PrintWriter(new FileWriter(resultPath));
        writer.println("program,all,resolved,time,AICT,FuncNum,AnalysisFuncNum");

        try (BufferedReader reader = new BufferedReader(new FileReader(inputFilePath))) {
            String line;
            int lineNumber = 0;

            while ((line = reader.readLine()) != null) {
                lineNumber++;
                line = line.trim();

                // 跳过空行
                if (line.isEmpty()) {
                    continue;
                }

                // 分割行内容为两列
                String[] columns = line.split(",");
                if (columns.length < 2) {
                    System.out.println("警告: 第 " + lineNumber + " 行格式不正确: " + line);
                    continue;
                }

                String name = columns[0];
                String expectedNumber = columns[1];

                // 构建JSON文件路径
                String jsonFilePath = String.format("/home/jackniu/scripts/emtaints/%s/result.json", name);

                try {
                    // 读取JSON文件内容
                    String jsonContent = new String(Files.readAllBytes(Paths.get(jsonFilePath)));

                    // 解析resolved字段的值
                    String actualNumber = extractValue(jsonContent, "resolved");
                    String allNumber = extractValue(jsonContent, "all");
                    String AnalysisFuncNum = extractValue(jsonContent, "processed_nums");
                    String FuncNum = extractValue(jsonContent, "total_functions");
                    String time = extractValue(jsonContent, "time");
                    String AICT = extractValue(jsonContent, "AICT");

                    writer.printf("%s,%s,%s,%s,%s,%s,%s\n", name, allNumber, actualNumber, time, AICT, FuncNum, AnalysisFuncNum);
                    writer.flush();

                    if (actualNumber != null) {
                        // 比较数字是否一致
                        if (!expectedNumber.equals(actualNumber)) {
                            System.out.printf("不一致: name=%s, 期望值=%s, 实际值=%s, JSON文件=%s%n",
                                            name, expectedNumber, actualNumber, jsonFilePath);
                        }
                    } else {
                        System.out.println("警告: JSON文件缺少resolved字段或格式不正确: " + jsonFilePath);
                    }

                } catch (IOException e) {
                    System.out.println("错误: 无法读取JSON文件: " + jsonFilePath + " - " + e.getMessage());
                } catch (Exception e) {
                    System.out.println("错误: 解析JSON文件时出错: " + jsonFilePath + " - " + e.getMessage());
                }
            }

        } catch (IOException e) {
            System.out.println("错误: 无法读取输入文件: " + inputFilePath + " - " + e.getMessage());
        }

        writer.close();
    }

    /**
     * 从JSON字符串中提取resolved字段的值
     * 简单的字符串解析，适用于简单的JSON格式
     */
    private static String extractValue(String jsonContent, String header) {
        // 查找"resolved"字段
        String searchPattern = String.format("\"%s\"", header);
        int resolvedIndex = jsonContent.indexOf(searchPattern);

        if (resolvedIndex == -1) {
            return null;
        }

        // 找到冒号位置
        int colonIndex = jsonContent.indexOf(":", resolvedIndex);
        if (colonIndex == -1) {
            return null;
        }

        // 找到值的开始位置（冒号后的第一个非空白字符）
        int valueStart = colonIndex + 1;
        while (valueStart < jsonContent.length() &&
               Character.isWhitespace(jsonContent.charAt(valueStart))) {
            valueStart++;
        }

        if (valueStart >= jsonContent.length()) {
            return null;
        }

        char valueStartChar = jsonContent.charAt(valueStart);
        int valueEnd;
        String resolvedValue;

        if (valueStartChar == '"') {
            // 字符串值
            valueEnd = jsonContent.indexOf("\"", valueStart + 1);
            if (valueEnd == -1) {
                return null;
            }
            resolvedValue = jsonContent.substring(valueStart + 1, valueEnd);
        } else {
            // 数字值或其他简单值（找到下一个逗号、大括号或方括号）
            valueEnd = valueStart + 1;
            while (valueEnd < jsonContent.length()) {
                char c = jsonContent.charAt(valueEnd);
                if (c == ',' || c == '}' || c == ']' || Character.isWhitespace(c)) {
                    break;
                }
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

        compareNameAndNumber(taskPath);
	}

	private void recurseProjectFolder(DomainFolder domainFolder) throws CancelledException,
			IOException {


        // 对ghidra项目中的文件进行排序
        DomainFile[] files = domainFolder.getFiles();
        Arrays.sort(files, new Comparator<DomainFile>() {
            @Override
            public int compare(DomainFile file1, DomainFile file2) {
                return file1.getName().toLowerCase().compareTo(file2.getName().toLowerCase());
            }
        });

        // 逐个处理文件
        for (DomainFile domainFile : files) {
            String fileName = domainFile.getName(); 

            // 如果文件名是 "ac9v"，直接跳过本次循环，进入下一个
            if ("ac9v".equals(fileName) || "wr940".equals(fileName)) {
                continue;
            }
            processDomainFile(domainFile);
        }

//         // 递归处理项目中的文件夹
// 		DomainFolder[] folders = domainFolder.getFolders();
// 		for (DomainFolder folder : folders) {
// 			recurseProjectFolder(folder);
// 		}
	}

	private void processDomainFile(DomainFile domainFile) throws CancelledException, IOException {
		// Do not follow folder-links or consider program links.  Using content type
		// to filter is best way to control this.  If program links should be considered
		// "Program.class.isAssignableFrom(domainFile.getDomainObjectClass())"
		// should be used.
		if (!ProgramContentHandler.PROGRAM_CONTENT_TYPE.equals(domainFile.getContentType())) {
			return; // skip non-Program files
		}
		if (domainFile.isVersioned() && !domainFile.isCheckedOut()) {
			println("WARNING! Skipping versioned file - not checked-out: " +
				domainFile.getPathname());
			return;
		}
		Program program = null;
		try {
			program =
				(Program) domainFile.getDomainObject(this, true /*upgrade*/,
					false /*don't recover*/, monitor);
			processProgram(program);
			saveProgram(program);
		}
		catch (Exception e) {
			println("ERROR! Failed to process file due to upgrade issue: " +
				domainFile.getPathname());
		}
		finally {
			if (program != null) {
				program.release(this);
			}
		}
	}

	private void processProgram(Program program) throws CancelledException, IOException {
		/* Do you program work here */
		println("Processing: " + program.getDomainFile().getPathname());
		monitor.setMessage("Processing: " + program.getDomainFile().getName());
		int id = program.startTransaction("Batch Script Transaction");
		try {
			GhidraState newState =
				new GhidraState(state.getTool(), state.getProject(), program, null, null, null);
// 			runScript(PRE_SUBSCRIPT_NAME, newState);
			runScript(SUBSCRIPT_NAME, newState);
		}
		catch (Exception e) {
			printerr("ERROR! Exception occurred while processing file: " +
				program.getDomainFile().getPathname());
			printerr("       " + e.getMessage());
			e.printStackTrace();
			return;
		}
		finally {
			program.endTransaction(id, true);
		}
	}
}
