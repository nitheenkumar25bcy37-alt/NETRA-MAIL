from pathlib import Path
import requests
import pymupdf
out=Path(__file__).parent/'stack_icons'; out.mkdir(exist_ok=True)
icons={0:('python','3776AB'),1:('fastapi','009688'),2:('javascript','D9B900'),3:('scikitlearn','F7931E'),4:('streamlit','FF4B4B'),5:('sqlite','003B57'),6:('opencv','5C3EE8'),10:('docker','2496ED'),11:('render','000000')}
for i,(slug,color) in icons.items():
 try:
  r=requests.get(f'https://cdn.jsdelivr.net/npm/simple-icons@v15/icons/{slug}.svg',timeout=15); r.raise_for_status()
  svg=r.text.replace('<svg ',f'<svg fill="#{color}" ')
  doc=pymupdf.open(stream=svg.encode(),filetype='svg'); pdf=pymupdf.open('pdf',doc.convert_to_pdf()); pdf[0].get_pixmap(matrix=pymupdf.Matrix(5,5),alpha=True).save(str(out/f'{i}.png'))
  print(slug,'downloaded')
 except Exception as e: print(slug,type(e).__name__)
