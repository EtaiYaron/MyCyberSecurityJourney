#include <iostream>  
#include <fstream>  
#include <stdexcept> 
#include "PersistencyProcess.h"
using namespace std;  

FILE* PersistencyProcess::Process(FILE* fptr) {  
  if (fptr == NULL) {  
      throw invalid_argument("problem with file pointer");  
  }  

  ofstream file;  
  file.open("filetoreturn.txt", ios::out);   

  if (!file.is_open()) {  
      throw invalid_argument("Error in creating file!");  
  }  

  char ch;  
  while ((ch = fgetc(fptr)) != EOF) {  
      file << ch;  
  }  

  file.close();   

  FILE* fileptr = fopen("filetoreturn.txt", "r+");   

  if (fileptr == NULL) {  
      throw invalid_argument("Error in reopening the file!");  
  }  

  return fileptr;  
}
