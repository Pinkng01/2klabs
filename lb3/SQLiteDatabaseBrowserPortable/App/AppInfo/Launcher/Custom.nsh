${SegmentFile}

${SegmentInit}
	${If} $Bits = 64
		Rename "$EXEDIR\App\SQLiteDatabaseBrowser32\translations" "$EXEDIR\App\SQLiteDatabaseBrowser64\translations"
	${Else}
		Rename "$EXEDIR\App\SQLiteDatabaseBrowser64\translations" "$EXEDIR\App\SQLiteDatabaseBrowser32\translations"
	${EndIf}
!macroend
