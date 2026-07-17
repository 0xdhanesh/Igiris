export const parentsPath=(search,baseline)=>`/api/parents?search=${encodeURIComponent(search)}&baseline_only=${baseline}`;
export const baselineBoundary=rows=>rows.reduce((latest,row)=>!latest||Date.parse(row.last_activity)>Date.parse(latest)?row.last_activity:latest,null);
