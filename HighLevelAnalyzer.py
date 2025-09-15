# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting


# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):

    # Define result types for display
    result_types = {
        'address': {
            'format': 'Device: {{data.name}}'
        },
        'flag': {
            'format': 'Flag: {{data.status}}'
        },
        'instruction': {
            'format': 'Instruction: {{data.op}}'
        },
        'fsm': {
            'format': 'Current FSM state: {{data.state}}'
        },
        'other': {
            'format': '{{data.new_data}}'
        }
    }

    def decode(self, frame: AnalyzerFrame):

        # Handle I2C address frame
        if frame.type == "address":
            addr = frame.data['address']
            is_read = frame.data['read']   # True = read, False = write

            if addr == 0x3C:
                device_name = "Everest"
                flag_status = "Pass"
            else:
                device_name = "Unknown"
                flag_status = "Fail"

            # Instruction type
            instr = "Read" if is_read else "Write"

            return [
                AnalyzerFrame('address', frame.start_time, frame.end_time, {
                    'name': f"{device_name} (0x{addr:02X})"
                }),
                AnalyzerFrame('flag', frame.start_time, frame.end_time, {
                    'status': flag_status
                }),
                AnalyzerFrame('instruction', frame.start_time, frame.end_time, {
                    'op': instr
                })
            ]

        # Handle I2C data frame
        if frame.type == "data":
            data_value = frame.data['data']
            return AnalyzerFrame('fsm', frame.start_time, frame.end_time, {
                'state': f"0x{data_value:02X}"
            })

        # For any other frames
        return AnalyzerFrame('other', frame.start_time, frame.end_time, {
            'new_data': f"type={frame.type}"
        })
