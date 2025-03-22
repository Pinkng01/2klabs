#Створіть словник, де ключі - це назви задач,
#  а значення - їх статус ("виконано", "в процесі", "очікує").
#  Напишіть функції для додавання, видалення та зміни статусу задач.
#  Додатково: створіть список задач, які мають статус "очікує".


tasks = {
    "task 1": "done",
    "task 2": "in progress",
    "task 3": "in queue",
}

def add_task(task_name, status="in queue"):
    tasks[task_name] = status

def remove_task(task_name):
    if task_name in tasks:
        del tasks[task_name]

def update_task_status(task_name, new_status):
    if task_name in tasks:
        tasks[task_name] = new_status

def get_pending_tasks():
    return [(task, status) for task, status in tasks.items() if status == "in queue"]

print("Task list:", tasks)

add_task("task 4")
print("Updated task list:", tasks)

update_task_status("task 2", "done")
print("Updated task list:", tasks)

remove_task("task 3")
print("Updated task list:", tasks)

pending_tasks = get_pending_tasks()
print("pending tasks:", pending_tasks)