add_subdirectory("Json")
add_subdirectory("spdlog")
add_subdirectory("libopenssl")

if (AUTHORIZATION)
    if (FINGER_VEIN)
        add_subdirectory("TGVein")
    endif()
  
  if(HF_CARD)
    add_subdirectory("libHF")
  endif()
endif()

if (FINGER_PRINT_LIVE31)
	add_subdirectory("Fingerprint_live31")
endif()
if(FR_SEETA)
	add_subdirectory("Face_Seeta")
endif()

if(HFREADER)
  add_subdirectory("HFReader")
endif()
