#include <iostream>
#include <fstream>
#include <filesystem>

void backupFile(const std::string& originalFilePath, const std::string& backupFilePath) {
    std::ifstream originalFile(originalFilePath, std::ios::binary);
    std::ofstream backupFile(backupFilePath, std::ios::binary);

    if (originalFile && backupFile) {
        backupFile << originalFile.rdbuf();
        std::cout << "Backup of " << originalFilePath << " created at " << backupFilePath << std::endl;
    } else {
        std::cerr << "Failed to create backup of " << originalFilePath << std::endl;
    }
}

void backupFiles(const std::string& originalFolderPath, const std::string& backupFolderPath) {
    std::filesystem::path folderPath = originalFolderPath;
    for (const auto& entry : std::filesystem::directory_iterator(folderPath)) {
        std::filesystem::path filePath = entry.path();
        std::filesystem::file_type type = std::filesystem::status(filePath).type();

        if (type == std::filesystem::file_type::directory) {
            std::filesystem::create_directories(backupFolderPath + "/" + filePath.filename().u8string());
            std::cout << "create dir" << std::endl;
            backupFiles(entry.path().u8string(), 
                    backupFolderPath + "/" + filePath.filename().u8string());
        }
        else
            backupFile(entry.path().u8string(), 
                    backupFolderPath + "/" + filePath.filename().u8string());
    }
}

int main(int argc, char* argv[]) {
    if (argc != 3)
        return 1;
    /* backupFiles("/Users/nikitaosovskiy/code/linuxspbu/orig", "/Users/nikitaosovskiy/code/linuxspbu/backup"); */
    backupFiles(argv[1], argv[2]);
    return 0;
}

