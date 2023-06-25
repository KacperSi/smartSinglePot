#include "nvs_config.h"
#include "nvsManager.hpp"

void NVSManager::initialize_nvs(){
  //Initialize NVS
  initialize_nvs_C();
}

NVSManager::NVSManager(){
  this->initialize_nvs();
}

NVSManager::~NVSManager(){
}